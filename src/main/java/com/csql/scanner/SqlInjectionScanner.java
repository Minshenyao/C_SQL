package com.csql.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.csql.config.ScannerConfig;
import com.csql.model.ScanResult;
import com.csql.model.ScanTask;
import com.csql.util.Md5Util;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SQL 注入扫描器核心类
 *
 * 实现 HttpHandler 接口处理 HTTP 流量
 * 实现 ContextMenuItemsProvider 接口提供右键菜单
 *
 * 主要功能：
 * 1. 监控 Proxy/Repeater 的 HTTP 流量
 * 2. 自动识别请求参数（GET/POST/JSON/Cookie）
 * 3. 使用 Payload 进行 SQL 注入测试
 * 4. 分析响应判断是否存在注入漏洞
 *
 * @author C_SQL Team
 * @version 2.0.0
 */
public class SqlInjectionScanner implements HttpHandler, ContextMenuItemsProvider {

    /**
     * Montoya API 实例
     */
    private final MontoyaApi api;

    /**
     * 扫描器配置
     */
    private final ScannerConfig config;

    /**
     * 日志记录器
     */
    private final Logging logging;

    /**
     * 扫描任务列表（线程安全）
     */
    private final CopyOnWriteArrayList<ScanTask> scanTasks = new CopyOnWriteArrayList<>();

    /**
     * 所有测试结果列表（线程安全）
     */
    private final CopyOnWriteArrayList<ScanResult> allResults = new CopyOnWriteArrayList<>();

    /**
     * 已扫描请求的 LRU 缓存（用于去重，最多缓存 10000 条）
     */
    private final Map<String, Long> scannedRequestCache = Collections.synchronizedMap(
            new LinkedHashMap<String, Long>(1000, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
                    // 保留最近 10000 条记录，超过则删除最老的
                    return size() > 10000;
                }
            }
    );

    /**
     * 请求速率限制器（令牌桶算法）
     * 默认每秒最多 10 个请求，避免触发 WAF
     */
    private final Semaphore rateLimiter = new Semaphore(10);

    /**
     * 速率限制器刷新线程
     */
    private final Thread rateLimiterRefreshThread;

    /**
     * 扫描计数器（原子操作保证线程安全）
     */
    private final AtomicInteger scanCounter = new AtomicInteger(0);

    /**
     * 数据变更监听器列表
     */
    private final List<DataChangeListener> listeners = new ArrayList<>();

    /**
     * 数据变更监听器接口
     */
    public interface DataChangeListener {
        void onTasksChanged();
        void onResultsChanged();
        void onLogMessage(String message);
    }

    /**
     * 构造函数
     *
     * @param api    Montoya API 实例
     * @param config 扫描器配置
     */
    public SqlInjectionScanner(MontoyaApi api, ScannerConfig config) {
        this.api = api;
        this.config = config;
        this.logging = api.logging();

        // 启动速率限制器刷新线程（每 100ms 释放一个令牌，实现每秒 10 个请求）
        rateLimiterRefreshThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(100); // 每 100ms 释放一个令牌
                    if (rateLimiter.availablePermits() < 10) {
                        rateLimiter.release();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        rateLimiterRefreshThread.setDaemon(true);
        rateLimiterRefreshThread.setName("C_SQL-RateLimiter");
        rateLimiterRefreshThread.start();
    }

    /**
     * 添加数据变更监听器
     *
     * @param listener 监听器
     */
    public void addDataChangeListener(DataChangeListener listener) {
        listeners.add(listener);
    }

    /**
     * 通知任务列表变更
     */
    private void notifyTasksChanged() {
        for (DataChangeListener listener : listeners) {
            SwingUtilities.invokeLater(listener::onTasksChanged);
        }
    }

    /**
     * 通知结果列表变更
     */
    private void notifyResultsChanged() {
        for (DataChangeListener listener : listeners) {
            SwingUtilities.invokeLater(listener::onResultsChanged);
        }
    }

    /**
     * 通知日志消息
     */
    private void notifyLogMessage(String message) {
        for (DataChangeListener listener : listeners) {
            listener.onLogMessage(message);
        }
    }

    // ==================== HttpHandler 接口实现 ====================

    /**
     * 处理即将发送的 HTTP 请求
     * 在此阶段不做处理，只是让请求继续
     *
     * @param httpRequestToBeSent 即将发送的请求
     * @return 继续执行的动作
     */
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        // 不修改请求，直接继续
        return RequestToBeSentAction.continueWith(httpRequestToBeSent);
    }

    /**
     * 处理收到的 HTTP 响应
     * 这是扫描的触发点，当收到响应时检查是否需要进行扫描
     *
     * @param httpResponseReceived 收到的响应
     * @return 继续执行的动作
     */
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        HttpResponseReceived responseReceived = httpResponseReceived;
        // 检查插件是否启用
        if (!config.isPluginEnabled()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // 获取请求来源工具
        ToolType toolType = responseReceived.toolSource().toolType();

        // 检查是否是需要监控的工具
        boolean shouldMonitor = false;
        if (toolType == ToolType.PROXY && config.isMonitorProxy()) {
            shouldMonitor = true;
        } else if (toolType == ToolType.REPEATER && config.isMonitorRepeater()) {
            shouldMonitor = true;
        }

        if (!shouldMonitor) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // 获取请求响应对象
        HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                responseReceived.initiatingRequest(),
                responseReceived
        );

        // 在新线程中执行扫描，避免阻塞 Burp 主线程
        Thread scanThread = new Thread(() -> {
            try {
                performScan(requestResponse, toolType.toolName());
            } catch (Exception e) {
                logging.logToError("扫描时发生错误: " + e.getMessage());
            }
        });
        scanThread.setName("C_SQL-Scanner-" + scanCounter.get());
        scanThread.start();

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    // ==================== ContextMenuItemsProvider 接口实现 ====================

    /**
     * 提供右键菜单项
     * 在 Proxy 和 Repeater 中添加 "Send to C_SQL" 菜单项
     *
     * @param event 上下文菜单事件
     * @return 菜单项列表
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // 只在 Proxy 和 Repeater 中显示菜单
        if (event.isFromTool(ToolType.PROXY, ToolType.REPEATER)) {
            JMenuItem sendToCSql = new JMenuItem("Send to C_SQL");

            sendToCSql.addActionListener(e -> {
                // 获取选中的请求
                List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();

                if (!selectedItems.isEmpty() && config.isPluginEnabled()) {
                    // 在新线程中执行扫描
                    Thread scanThread = new Thread(() -> {
                        try {
                            performScan(selectedItems.get(0), "Extension");
                        } catch (Exception ex) {
                            logging.logToError("手动扫描时发生错误: " + ex.getMessage());
                        }
                    });
                    scanThread.setName("C_SQL-ManualScan");
                    scanThread.start();
                }
            });

            menuItems.add(sendToCSql);
        }

        return menuItems;
    }

    // ==================== 核心扫描逻辑 ====================

    /**
     * 执行 SQL 注入扫描
     *
     * @param baseRequestResponse 原始请求响应
     * @param toolSource          请求来源工具名称
     */
    public void performScan(HttpRequestResponse baseRequestResponse, String toolSource) {
        // 获取请求对象
        HttpRequest request = baseRequestResponse.request();

        // 获取 URL
        String urlString = request.url();
        String baseUrl = urlString.split("\\?")[0];

        // 检查白名单/黑名单
        if (config.isWhitelistEnabled() && !config.urlMatchesList(baseUrl, config.getWhitelistUrls())) {
            return;
        }
        if (config.isBlacklistEnabled() && config.urlMatchesList(baseUrl, config.getBlacklistUrls())) {
            return;
        }

        // 检查是否为静态资源
        String[] urlParts = baseUrl.split("\\.");
        if (urlParts.length > 1) {
            String extension = urlParts[urlParts.length - 1];
            if (config.isStaticResource(extension)) {
                return;
            }
        }

        // 检查响应是否为二进制文件（图片等）
        if (isBinaryResponse(baseRequestResponse)) {
            return;
        }

        // 获取所有参数
        List<ParsedHttpParameter> parameters = request.parameters();

        // 生成请求的唯一标识（用于去重）
        String requestHashSeed = baseUrl;
        boolean hasTestableParams = false;

        for (ParsedHttpParameter param : parameters) {
            HttpParameterType type = param.type();

            // 只处理支持的参数类型
            if (type == HttpParameterType.URL ||
                    type == HttpParameterType.BODY ||
                    type == HttpParameterType.JSON ||
                    (type == HttpParameterType.COOKIE && config.isTestCookieParams())) {

                hasTestableParams = true;
                requestHashSeed += "+" + param.name();
            }
        }

        // 添加请求方法到哈希
        requestHashSeed += "+" + request.method();

        // 计算 MD5
        String requestMd5 = Md5Util.md5(requestHashSeed);

        // 检查是否已扫描过（手动触发的除外）
        synchronized (scannedRequestCache) {
            if (scannedRequestCache.containsKey(requestMd5) && !"Extension".equals(toolSource)) {
                return;
            }
            scannedRequestCache.put(requestMd5, System.currentTimeMillis());
        }

        // 如果没有可测试的参数，直接返回
        if (!hasTestableParams) {
            return;
        }

        // 获取原始响应长度
        int originalResponseLength = 0;
        if (baseRequestResponse.response() != null) {
            originalResponseLength = baseRequestResponse.response().toByteArray().length();
        }
        if (originalResponseLength <= 0) {
            return;
        }

        // 创建扫描任务
        int taskId = scanCounter.getAndIncrement();
        ScanTask task = new ScanTask(
                taskId,
                toolSource,
                baseRequestResponse,
                urlString,
                originalResponseLength,
                requestMd5
        );
        scanTasks.add(task);
        notifyTasksChanged();

        // 状态标记（使用布尔标志避免重复）
        boolean hasVulnerability = false;  // 发现可能的注入点
        boolean hasHttp500 = false;        // 有 500 错误
        boolean hasErrorPattern = false;   // 匹配到报错关键词
        boolean hasTMarker = false;        // 单引号500双引号不500

        // 遍历参数进行测试
        for (ParsedHttpParameter param : parameters) {
            HttpParameterType paramType = param.type();

            // 检查参数类型是否需要测试
            if (paramType != HttpParameterType.URL &&
                    paramType != HttpParameterType.BODY &&
                    paramType != HttpParameterType.JSON &&
                    !(paramType == HttpParameterType.COOKIE && config.isTestCookieParams())) {
                continue;
            }

            String paramName = param.name();
            String paramValue = param.value();

            // 获取要使用的 Payload 列表（分级优化）
            List<String> payloads = getOptimizedPayloads(paramValue);

            // 用于比较响应长度的基准值
            int baselineResponseLength = 0;
            int previousStatusCode = 0;
            int payloadIndex = 0;

            // 遍历 Payload 进行测试
            for (String payload : payloads) {
                // 应用速率限制
                try {
                    if (!rateLimiter.tryAcquire(5, TimeUnit.SECONDS)) {
                        logging.logToError("速率限制：等待令牌超时，跳过该 Payload");
                        continue;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }

                // 请求延迟
                delayBetweenRequests();

                // 确定实际发送的参数值
                String valueForSend = paramValue;
                if (config.isUseCustomPayloads() && config.isEmptyParamValues()
                        && !payload.equals("'") && !payload.equals("''")
                        && !payload.equals("-1") && !payload.equals("-0")) {
                    valueForSend = "";
                }

                // 构造注入后的请求
                HttpRequest attackRequest;
                if (paramType == HttpParameterType.JSON) {
                    // JSON 参数需要特殊处理
                    attackRequest = buildJsonPayloadRequest(request, paramName, paramValue, payload);
                } else {
                    // 普通参数使用 withUpdatedParameters
                    HttpParameter newParam = HttpParameter.parameter(
                            paramName,
                            valueForSend + payload,
                            paramType
                    );
                    attackRequest = request.withUpdatedParameters(newParam);
                }

                // 发送请求并计时
                long startTime = System.currentTimeMillis();
                HttpRequestResponse attackResponse = api.http().sendRequest(attackRequest);
                long endTime = System.currentTimeMillis();
                int responseTime = (int) (endTime - startTime);

                // 获取响应状态码
                int statusCode = 0;
                if (attackResponse.response() != null) {
                    statusCode = attackResponse.response().statusCode();
                }

                // 获取响应长度
                int attackResponseLength = 0;
                if (attackResponse.response() != null) {
                    attackResponseLength = attackResponse.response().toByteArray().length();
                }

                // 分析变化标记
                String changeMarker = analyzeResponse(
                        payload, payloadIndex, baselineResponseLength,
                        attackResponseLength, originalResponseLength,
                        statusCode, previousStatusCode, responseTime, requestMd5
                );

                // 检查报错关键词
                if (attackResponse.response() != null) {
                    String responseBody = attackResponse.response().bodyToString();
                    String[] errorPatterns = config.getErrorPatterns();

                    for (String patternText : errorPatterns) {
                        try {
                            Pattern pattern = Pattern.compile(patternText.trim());
                            if (pattern.matcher(responseBody).find()) {
                                changeMarker += " Err";
                                hasErrorPattern = true;
                                notifyLogMessage("Err: ID -> " + taskId + " -> " + paramName + " -> " + patternText.trim());
                                break;
                            }
                        } catch (Exception e) {
                            // 忽略无效的正则表达式
                        }
                    }
                }

                // 检查响应时间（自定义 Payload 才会触发）
                if (changeMarker.contains("time > 5")) {
                    notifyLogMessage("time > 5: ID -> " + taskId + " -> " + paramName);
                }

                // 更新状态标记
                if (changeMarker.contains("✔")) {
                    hasVulnerability = true;
                }
                if (statusCode == 500) {
                    hasHttp500 = true;
                }

                // 记录结果
                ScanResult result = new ScanResult(
                        taskId,
                        attackResponse,
                        paramName,
                        paramValue + payload,
                        changeMarker,
                        requestMd5,
                        responseTime,
                        statusCode
                );
                allResults.add(result);

                // 更新基准值
                if (payloadIndex == 0) {
                    baselineResponseLength = attackResponseLength;
                }

                // 检查单引号 500 而双引号不 500 的情况
                if (payloadIndex == 1 && previousStatusCode == 500 && statusCode != 500) {
                    // 找到之前的单引号结果并追加标记
                    for (int i = allResults.size() - 2; i >= 0; i--) {
                        ScanResult prevResult = allResults.get(i);
                        if (prevResult.getTaskMd5().equals(requestMd5)
                                && prevResult.getParameter().equals(paramName)
                                && prevResult.getResponseCode() == 500) {
                            prevResult.appendChangeMarker(" 𝙩");
                            hasTMarker = true;
                            notifyLogMessage("𝙩: ID -> " + taskId + " -> " + paramName);
                            break;
                        }
                    }
                }

                previousStatusCode = statusCode;
                payloadIndex++;
            }
        }

        // 更新任务状态（简洁显示）
        StringBuilder finalState = new StringBuilder("end!");
        if (hasVulnerability) finalState.append(" ✔");
        if (hasHttp500) finalState.append(" 𝟓");
        if (hasErrorPattern) finalState.append(" Err");
        if (hasTMarker) finalState.append(" 𝙩");
        task.setState(finalState.toString());

        // 通知数据变更
        notifyTasksChanged();
        notifyResultsChanged();
    }

    /**
     * 分析响应并生成变化标记
     */
    private String analyzeResponse(String payload, int payloadIndex,
                                   int baselineLength, int attackLength,
                                   int originalLength, int statusCode,
                                   int previousStatusCode, int responseTime,
                                   String requestMd5) {
        String changeMarker = "";

        // 非基准 Payload 的分析
        if (!payload.equals("'") && !payload.equals("-1") && baselineLength != 0) {
            if (!payload.equals("''") && !payload.equals("-0")) {
                // 自定义 Payload
                if (responseTime >= 5000) {
                    changeMarker = "time > 5";
                    changeMarker += " ✔";
                } else {
                    changeMarker = "diy payload";
                }
            } else {
                // 双引号或 -0 Payload
                if (baselineLength == attackLength) {
                    changeMarker = "";
                } else if (attackLength == originalLength) {
                    changeMarker = "✔ ==> ?";
                } else {
                    int lengthDiff = baselineLength - attackLength;
                    changeMarker = "✔ " + lengthDiff;
                }
            }
        }

        // HTTP 500 错误处理
        if (statusCode == 500) {
            if (changeMarker.isEmpty()) {
                changeMarker = "✔ 𝟓";
            } else {
                if (!changeMarker.contains("✔")) {
                    changeMarker += " ✔";
                }
                if (!changeMarker.contains("𝟓")) {
                    changeMarker += " 𝟓";
                }
            }
        }

        return changeMarker;
    }

    /**
     * 构建 JSON 参数的 Payload 请求
     */
    private HttpRequest buildJsonPayloadRequest(HttpRequest request, String paramName,
                                                 String paramValue, String payload) {
        // 获取原始请求体
        String body = request.bodyToString();

        // 简单替换：找到参数并注入 Payload
        // 处理字符串类型的 JSON 值
        String pattern = "\"" + paramName + "\"\\s*:\\s*\"" + Pattern.quote(paramValue) + "\"";
        String replacement = "\"" + paramName + "\":\"" + paramValue + payload + "\"";
        body = body.replaceFirst(pattern, replacement);

        // 处理数字类型的 JSON 值
        pattern = "\"" + paramName + "\"\\s*:\\s*" + Pattern.quote(paramValue) + "([,}\\]])";
        replacement = "\"" + paramName + "\":\"" + paramValue + payload + "\"$1";
        body = body.replaceFirst(pattern, replacement);

        return request.withBody(body);
    }

    /**
     * 检查响应是否为二进制文件
     */
    private boolean isBinaryResponse(HttpRequestResponse requestResponse) {
        if (requestResponse.response() == null) {
            return false;
        }

        byte[] body = requestResponse.response().body().getBytes();
        if (body.length < 2) {
            return false;
        }

        // 检查常见的二进制文件魔数
        // JPEG
        if (body[0] == (byte) 0xFF && body[1] == (byte) 0xD8) {
            return true;
        }

        // PNG
        if (body.length >= 4 && body[0] == (byte) 0x89 && body[1] == 0x50
                && body[2] == 0x4E && body[3] == 0x47) {
            return true;
        }

        // GIF
        if (body[0] == 0x47 && body[1] == 0x49) {
            return true;
        }

        return false;
    }

    /**
     * 请求延迟
     */
    private void delayBetweenRequests() {
        int delayMs = config.getRequestDelayMs();
        if (delayMs > 0) {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * 记录日志消息
     */
    private void logMessage(String message) {
        logging.logToOutput(message);
    }

    // ==================== 数据访问方法 ====================

    /**
     * 获取扫描任务列表
     */
    public List<ScanTask> getScanTasks() {
        return new ArrayList<>(scanTasks);
    }

    /**
     * 获取所有扫描结果
     */
    public List<ScanResult> getAllResults() {
        return new ArrayList<>(allResults);
    }

    /**
     * 获取指定任务的扫描结果
     */
    public List<ScanResult> getResultsByTaskMd5(String taskMd5) {
        List<ScanResult> results = new ArrayList<>();
        for (ScanResult result : allResults) {
            if (result.getTaskMd5().equals(taskMd5)) {
                results.add(result);
            }
        }
        return results;
    }

    /**
     * 清空所有数据
     */
    public void clearAll() {
        scanTasks.clear();
        allResults.clear();
        synchronized (scannedRequestCache) {
            scannedRequestCache.clear();
        }
        scanCounter.set(0);
        notifyTasksChanged();
        notifyResultsChanged();
    }

    // ==================== Payload 优化逻辑 ====================

    /**
     * 获取优化后的 Payload 列表（分级测试）
     * 优先级：基础测试 -> 布尔盲注 -> 报错注入 -> 时间盲注
     *
     * @param paramValue 参数值
     * @return 优化后的 Payload 列表
     */
    private List<String> getOptimizedPayloads(String paramValue) {
        List<String> optimizedPayloads = new ArrayList<>();
        List<String> allPayloads = config.getEffectivePayloads();

        // 第一级：基础语法测试（优先级最高）
        List<String> basicPayloads = Arrays.asList("'", "\"", "`", "')", "\")", "`)", "'))", "\"))", "`))");

        // 第二级：布尔盲注
        List<String> booleanPayloads = Arrays.asList(
                "'%20AND%20'1'='1", "'%20AND%20'1'='2",
                "\"%20AND%20\"1\"=\"1", "\"%20AND%20\"1\"=\"2",
                "'%20OR%20'1'='1", "'%20OR%20'1'='2"
        );

        // 第三级：联合查询和报错注入
        List<String> unionAndErrorPayloads = new ArrayList<>();
        for (String payload : allPayloads) {
            if (payload.contains("UNION") || payload.contains("ORDER BY") ||
                    payload.contains("extractvalue") || payload.contains("convert") ||
                    payload.contains("cast") || payload.contains("utl_inaddr")) {
                unionAndErrorPayloads.add(payload);
            }
        }

        // 第四级：时间盲注（最慢，最后测试）
        List<String> timeBasedPayloads = new ArrayList<>();
        for (String payload : allPayloads) {
            if (payload.contains("SLEEP") || payload.contains("WAITFOR") ||
                    payload.contains("pg_sleep") || payload.contains("DBMS_LOCK")) {
                timeBasedPayloads.add(payload);
            }
        }

        // 按优先级添加
        for (String payload : allPayloads) {
            if (basicPayloads.contains(payload)) {
                optimizedPayloads.add(payload);
            }
        }
        for (String payload : allPayloads) {
            if (booleanPayloads.contains(payload)) {
                optimizedPayloads.add(payload);
            }
        }
        optimizedPayloads.addAll(unionAndErrorPayloads);
        optimizedPayloads.addAll(timeBasedPayloads);

        // 添加其他未分类的 Payload
        for (String payload : allPayloads) {
            if (!optimizedPayloads.contains(payload)) {
                optimizedPayloads.add(payload);
            }
        }

        // 如果启用了数字参数测试，对纯数字参数添加额外 Payload
        if (config.isTestNumericParams() && paramValue.matches("[0-9]+")) {
            optimizedPayloads.add("-1");
            optimizedPayloads.add("-0");
        }

        return optimizedPayloads;
    }
}
