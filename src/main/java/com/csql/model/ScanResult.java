package com.csql.model;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * 扫描结果实体类
 *
 * 表示单个 Payload 的扫描结果
 * 每个参数的每个 Payload 测试都会产生一个 ScanResult 实例
 *
 * @author C_SQL Team
 * @version 2.0.0
 */
public class ScanResult {

    /**
     * 所属扫描任务的 ID
     */
    private final int taskId;

    /**
     * HTTP 请求响应对象（包含注入 Payload 后的请求和响应）
     */
    private final HttpRequestResponse requestResponse;

    /**
     * 测试的参数名
     */
    private final String parameter;

    /**
     * 参数值 + Payload（实际发送的值）
     */
    private final String payload;

    /**
     * 变化标记
     * 用于标识扫描结果的特征，如：
     * - ✔ 表示发现异常
     * - ✔ ==> ? 表示响应长度恢复
     * - ✔ 数字 表示响应长度差异
     * - 𝟓 表示 HTTP 500 错误
     * - 𝙩 表示单引号 500 而双引号不 500
     * - Err 表示匹配到报错关键词
     * - time > 5 表示响应时间超过 5 秒
     */
    private volatile String changeMarker;

    /**
     * 所属任务的 MD5
     * 用于关联扫描任务
     */
    private final String taskMd5;

    /**
     * 请求耗时（毫秒）
     */
    private final int responseTime;

    /**
     * HTTP 响应状态码
     */
    private final int responseCode;

    /**
     * 构造函数
     *
     * @param taskId          任务 ID
     * @param requestResponse HTTP 请求响应
     * @param parameter       参数名
     * @param payload         参数值 + Payload
     * @param changeMarker    变化标记
     * @param taskMd5         任务 MD5
     * @param responseTime    响应耗时
     * @param responseCode    响应状态码
     */
    public ScanResult(int taskId, HttpRequestResponse requestResponse, String parameter,
                      String payload, String changeMarker, String taskMd5,
                      int responseTime, int responseCode) {
        this.taskId = taskId;
        this.requestResponse = requestResponse;
        this.parameter = parameter;
        this.payload = payload;
        this.changeMarker = changeMarker;
        this.taskMd5 = taskMd5;
        this.responseTime = responseTime;
        this.responseCode = responseCode;
    }

    // ==================== Getter 方法 ====================

    public int getTaskId() {
        return taskId;
    }

    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public String getParameter() {
        return parameter;
    }

    public String getPayload() {
        return payload;
    }

    public String getChangeMarker() {
        return changeMarker;
    }

    /**
     * 设置变化标记
     *
     * @param changeMarker 新的变化标记
     */
    public void setChangeMarker(String changeMarker) {
        this.changeMarker = changeMarker;
    }

    /**
     * 追加变化标记
     *
     * @param marker 要追加的标记
     */
    public void appendChangeMarker(String marker) {
        this.changeMarker = this.changeMarker + marker;
    }

    public String getTaskMd5() {
        return taskMd5;
    }

    public int getResponseTime() {
        return responseTime;
    }

    public int getResponseCode() {
        return responseCode;
    }

    /**
     * 获取响应长度
     *
     * @return 响应体长度
     */
    public int getResponseLength() {
        if (requestResponse != null && requestResponse.response() != null) {
            return requestResponse.response().toByteArray().length();
        }
        return 0;
    }
}
