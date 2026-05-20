package com.csql.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.csql.config.ScannerConfig;
import com.csql.model.ScanResult;
import com.csql.model.ScanTask;
import com.csql.scanner.SqlInjectionScanner;
import com.csql.ui.panel.ConfigPanel;
import com.csql.ui.table.ResultTableModel;
import com.csql.ui.table.TaskTableModel;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.List;

/**
 * 主标签页界面类
 *
 * 负责构建和管理插件的主界面
 * 包括任务列表、结果列表、请求/响应查看器、配置面板等
 *
 * @author C_SQL Team
 * @version 2.0.0
 */
public class MainTab implements SqlInjectionScanner.DataChangeListener {

    /**
     * Montoya API 实例
     */
    private final MontoyaApi api;

    /**
     * 扫描器配置
     */
    private final ScannerConfig config;

    /**
     * SQL 注入扫描器
     */
    private final SqlInjectionScanner scanner;

    /**
     * 主面板容器
     */
    private final JSplitPane mainSplitPane;

    /**
     * 任务表格模型
     */
    private final TaskTableModel taskTableModel;

    /**
     * 结果表格模型
     */
    private final ResultTableModel resultTableModel;

    /**
     * 任务表格
     */
    private JTable taskTable;

    /**
     * 结果表格
     */
    private JTable resultTable;

    /**
     * 请求编辑器（只读）
     */
    private HttpRequestEditor requestEditor;

    /**
     * 响应编辑器（只读）
     */
    private HttpResponseEditor responseEditor;

    /**
     * 日志文本区域
     */
    private JTextArea logTextArea;

    /**
     * 左侧垂直分割面板（用于同步右侧分隔线位置）
     */
    private JSplitPane leftVerticalSplit;

    /**
     * 当前选中的任务 MD5
     */
    private String selectedTaskMd5 = "";

    /**
     * 当前选中的任务行索引
     */
    private int selectedTaskRow = 0;

    /**
     * 当前显示的请求/响应标识，避免重复刷新导致滚动位置重置
     */
    private String currentDisplayedResponseId = "";

    /**
     * 标志位：是否正在程序化更新表格选择（非用户主动选择）
     * 用于区分用户点击和程序为保持选择状态而触发的选择事件
     */
    private boolean isProgrammaticSelection = false;

    /**
     * 构造函数
     *
     * @param api     Montoya API 实例
     * @param config  扫描器配置
     * @param scanner SQL 注入扫描器
     */
    public MainTab(MontoyaApi api, ScannerConfig config, SqlInjectionScanner scanner) {
        this.api = api;
        this.config = config;
        this.scanner = scanner;

        // 创建表格模型
        this.taskTableModel = new TaskTableModel(scanner);
        this.resultTableModel = new ResultTableModel(scanner);

        // 注册数据变更监听
        scanner.addDataChangeListener(this);

        // 构建主界面
        this.mainSplitPane = buildMainPanel();
    }

    /**
     * 获取主面板组件
     *
     * @return 主面板组件
     */
    public Component getComponent() {
        return mainSplitPane;
    }

    /**
     * 构建主面板
     *
     * @return 主分割面板
     */
    private JSplitPane buildMainPanel() {
        // 主水平分割面板（左侧数据区 | 右侧配置区）
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // 构建左侧数据区域
        JSplitPane leftPanel = buildLeftPanel();

        // 构建右侧配置区域
        JTabbedPane configTabs = buildConfigTabs();
        configTabs.setPreferredSize(new Dimension(380, 900));

        // 设置分割面板属性
        mainSplit.setLeftComponent(leftPanel);
        mainSplit.setRightComponent(configTabs);
        mainSplit.setResizeWeight(1.0);  // 窗口变化时优先调整左侧大小

        // 监听窗口大小变化，动态调整分隔位置
        mainSplit.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                int totalWidth = mainSplit.getWidth();
                int configWidth = configTabs.getPreferredSize().width;
                if (totalWidth > configWidth + 200) {
                    mainSplit.setDividerLocation(totalWidth - configWidth);
                }
            }
        });

        return mainSplit;
    }

    /**
     * 构建左侧数据面板
     *
     * @return 左侧分割面板
     */
    private JSplitPane buildLeftPanel() {
        // 垂直分割（上：表格区 | 下：消息查看器）
        leftVerticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 构建表格区域（水平分割：任务表格 | 结果表格）
        JSplitPane tablesSplit = buildTablesPanel();

        // 构建消息查看器标签页
        JTabbedPane messageTabs = buildMessageTabs();

        // 设置分割面板属性
        leftVerticalSplit.setTopComponent(tablesSplit);
        leftVerticalSplit.setBottomComponent(messageTabs);
        leftVerticalSplit.setResizeWeight(0.5);  // 各占 50%

        // 设置最小尺寸
        tablesSplit.setMinimumSize(new Dimension(0, 0));
        messageTabs.setMinimumSize(new Dimension(0, 0));

        // 在组件显示后设置分隔位置为 50%
        leftVerticalSplit.addComponentListener(new java.awt.event.ComponentAdapter() {
            private boolean initialized = false;
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                if (!initialized && leftVerticalSplit.getHeight() > 0) {
                    leftVerticalSplit.setDividerLocation(0.5);
                    initialized = true;
                }
            }
        });

        return leftVerticalSplit;
    }

    /**
     * 构建表格面板
     *
     * @return 表格分割面板
     */
    private JSplitPane buildTablesPanel() {
        // 水平分割（左：任务表格 | 右：结果表格）
        JSplitPane tablesSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        // 任务表格
        taskTable = new JTable(taskTableModel);
        taskTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        taskTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onTaskSelected();
            }
        });
        JScrollPane taskScroll = new JScrollPane(taskTable);

        // 结果表格
        resultTable = new JTable(resultTableModel);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onResultSelected();
            }
        });
        JScrollPane resultScroll = new JScrollPane(resultTable);

        // 设置分割面板属性
        tablesSplit.setLeftComponent(taskScroll);
        tablesSplit.setRightComponent(resultScroll);
        tablesSplit.setResizeWeight(0.5);
        tablesSplit.setDividerLocation(0.5);

        return tablesSplit;
    }

    /**
     * 构建消息查看器标签页
     *
     * @return 消息标签页面板
     */
    private JTabbedPane buildMessageTabs() {
        JTabbedPane messageTabs = new JTabbedPane();

        // 创建请求编辑器（只读模式）
        requestEditor = api.userInterface().createHttpRequestEditor();

        // 创建响应编辑器（只读模式）
        responseEditor = api.userInterface().createHttpResponseEditor();

        // 添加标签页
        messageTabs.addTab("Request", requestEditor.uiComponent());
        messageTabs.addTab("Response", responseEditor.uiComponent());

        return messageTabs;
    }

    /**
     * 构建配置标签页
     *
     * @return 配置标签页面板
     */
    private JTabbedPane buildConfigTabs() {
        JTabbedPane configTabs = new JTabbedPane();

        // 基础设置标签页
        JSplitPane baseTabSplit = buildBaseSettingsTab();
        configTabs.addTab("基础设置", baseTabSplit);

        // 自定义 Payload 标签页
        JSplitPane payloadTabSplit = buildPayloadTab();
        configTabs.addTab("自定义payload语句", payloadTabSplit);

        // 自定义报错信息标签页
        JSplitPane errorTabSplit = buildErrorPatternsTab();
        configTabs.addTab("自定义报错信息", errorTabSplit);

        return configTabs;
    }

    /**
     * 构建基础设置标签页
     */
    private JSplitPane buildBaseSettingsTab() {
        // 使用 ConfigPanel 构建设置面板
        ConfigPanel configPanel = new ConfigPanel(config, scanner, this::appendLog);

        // 日志面板
        JPanel logPanel = buildLogPanel();

        // 垂直分割（上：设置 | 下：日志）
        JSplitPane baseTabSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        baseTabSplit.setTopComponent(new JScrollPane(configPanel.getComponent()));
        baseTabSplit.setBottomComponent(logPanel);
        baseTabSplit.setMinimumSize(new Dimension(0, 0));

        // 监听左侧分隔线位置变化，同步右侧分隔线
        leftVerticalSplit.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, evt -> {
            SwingUtilities.invokeLater(() -> alignDivider(leftVerticalSplit, baseTabSplit));
        });

        // 初始化时也同步一次
        baseTabSplit.addComponentListener(new java.awt.event.ComponentAdapter() {
            private boolean initialized = false;
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                if (!initialized && baseTabSplit.getHeight() > 0) {
                    SwingUtilities.invokeLater(() -> alignDivider(leftVerticalSplit, baseTabSplit));
                    initialized = true;
                }
            }
        });

        return baseTabSplit;
    }

    /**
     * 对齐两个垂直分割面板的分隔线位置
     *
     * @param source 参考的分割面板（左侧）
     * @param target 要同步的分割面板（右侧）
     */
    private void alignDivider(JSplitPane source, JSplitPane target) {
        if (source == null || target == null) return;
        if (source.getHeight() <= 0 || target.getHeight() <= 0) return;

        try {
            // 获取左侧分隔线在主面板中的 Y 坐标
            int sourceLocation = source.getDividerLocation();
            Point sourcePoint = SwingUtilities.convertPoint(source, 0, sourceLocation, mainSplitPane);

            // 计算右侧分隔线应该在的位置
            Point targetTop = SwingUtilities.convertPoint(target, 0, 0, mainSplitPane);
            int desiredLocation = sourcePoint.y - targetTop.y;

            // 限制在有效范围内
            if (desiredLocation < 0) desiredLocation = 0;
            int maxLocation = Math.max(0, target.getHeight() - target.getDividerSize());
            if (desiredLocation > maxLocation) desiredLocation = maxLocation;

            target.setDividerLocation(desiredLocation);
        } catch (Exception ignored) {
        }
    }

    /**
     * 构建日志面板
     */
    private JPanel buildLogPanel() {
        JPanel logPanel = new JPanel(new BorderLayout());

        // 清空日志按钮
        JButton clearLogButton = new JButton("清空日志");
        clearLogButton.addActionListener(e -> logTextArea.setText(""));

        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        headerPanel.add(clearLogButton);

        // 日志文本区域
        logTextArea = new JTextArea();
        logTextArea.setEditable(false);
        JScrollPane logScroll = new JScrollPane(logTextArea);

        // 简化布局：按钮在上，日志在下
        logPanel.add(headerPanel, BorderLayout.NORTH);
        logPanel.add(logScroll, BorderLayout.CENTER);

        return logPanel;
    }

    /**
     * 构建 Payload 标签页
     */
    private JSplitPane buildPayloadTab() {
        // 选项面板（与报错信息标签页布局一致）
        JCheckBox customPayloadCheckbox = new JCheckBox("自定义payload (勾选进行测试)", config.isUseCustomPayloads());
        JButton saveButton = new JButton("加载/保存payload");
        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        headerPanel.add(customPayloadCheckbox);
        headerPanel.add(saveButton);

        // Payload 文本区域（使用默认字体，与报错信息标签页保持一致）
        JTextArea payloadTextArea = new JTextArea(config.getCustomPayloadText(), 18, 16);
        payloadTextArea.setEditable(config.isUseCustomPayloads());
        payloadTextArea.setBackground(config.isUseCustomPayloads() ? Color.WHITE : Color.LIGHT_GRAY);
        JScrollPane payloadScroll = new JScrollPane(payloadTextArea);

        // 事件监听
        customPayloadCheckbox.addItemListener(e -> {
            boolean selected = customPayloadCheckbox.isSelected();
            config.setUseCustomPayloads(selected);
            payloadTextArea.setEditable(selected);
            payloadTextArea.setBackground(selected ? Color.WHITE : Color.LIGHT_GRAY);
            // 勾选时同步加载文本框中的 payload
            if (selected) {
                config.setCustomPayloadText(payloadTextArea.getText());
            }
        });

        // 保存按钮事件：先加载文本框内容到配置，再保存到文件
        saveButton.addActionListener(e -> {
            // 先加载文本框内容到配置
            config.setCustomPayloadText(payloadTextArea.getText());
            // 再保存到 YAML 配置文件
            config.saveToYaml();
        });

        // 分割面板
        JSplitPane payloadSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        payloadSplit.setTopComponent(headerPanel);
        payloadSplit.setBottomComponent(payloadScroll);

        return payloadSplit;
    }

    /**
     * 构建报错关键词标签页
     */
    private JSplitPane buildErrorPatternsTab() {
        // 选项面板
        JCheckBox customErrorCheckbox = new JCheckBox("自定义报错信息（支持re表达式）", true);
        JButton saveButton = new JButton("加载/保存报错");
        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        headerPanel.add(customErrorCheckbox);
        headerPanel.add(saveButton);

        // 报错关键词文本区域
        JTextArea errorTextArea = new JTextArea(config.getCustomErrorPatterns(), 18, 16);
        errorTextArea.setEditable(false);
        errorTextArea.setBackground(Color.LIGHT_GRAY);
        JScrollPane errorScroll = new JScrollPane(errorTextArea);

        // 事件监听
        customErrorCheckbox.addItemListener(e -> {
            boolean selected = customErrorCheckbox.isSelected();
            if (selected) {
                config.setCustomErrorPatterns(errorTextArea.getText());
                errorTextArea.setEditable(false);
                errorTextArea.setBackground(Color.LIGHT_GRAY);
            } else {
                errorTextArea.setEditable(true);
                errorTextArea.setBackground(Color.WHITE);
            }
        });

        // 保存按钮事件
        saveButton.addActionListener(e -> {
            config.setCustomErrorPatterns(errorTextArea.getText());
            config.saveToYaml();  // 保存到 YAML 配置文件
        });

        // 分割面板
        JSplitPane errorSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        errorSplit.setTopComponent(headerPanel);
        errorSplit.setBottomComponent(errorScroll);

        return errorSplit;
    }

    // ==================== 事件处理方法 ====================

    /**
     * 任务表格选中事件处理
     */
    private void onTaskSelected() {
        if (isProgrammaticSelection) {
            return;
        }

        int selectedRow = taskTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }

        List<ScanTask> tasks = scanner.getScanTasks();
        if (selectedRow >= tasks.size()) {
            return;
        }

        ScanTask task = tasks.get(selectedRow);
        selectedTaskMd5 = task.getRequestMd5();
        selectedTaskRow = selectedRow;

        // 更新结果表格，显示该任务的结果
        resultTableModel.setCurrentTaskMd5(selectedTaskMd5);
        resultTableModel.fireTableDataChanged();

        // 更新请求/响应查看器（只在内容变化时更新，避免滚动位置重置）
        HttpRequestResponse requestResponse = task.getRequestResponse();
        String responseId = "task:" + selectedTaskMd5;
        if (requestResponse != null && !responseId.equals(currentDisplayedResponseId)) {
            currentDisplayedResponseId = responseId;
            if (requestResponse.request() != null) {
                requestEditor.setRequest(requestResponse.request());
            }
            if (requestResponse.response() != null) {
                responseEditor.setResponse(requestResponse.response());
            }
        }
    }

    /**
     * 结果表格选中事件处理
     */
    private void onResultSelected() {
        if (isProgrammaticSelection) {
            return;
        }
        int selectedRow = resultTable.getSelectedRow();
        if (selectedRow < 0) {
            return;
        }

        List<ScanResult> results = scanner.getResultsByTaskMd5(selectedTaskMd5);
        if (selectedRow >= results.size()) {
            return;
        }

        ScanResult result = results.get(selectedRow);

        // 更新请求/响应查看器（只在内容变化时更新，避免滚动位置重置）
        HttpRequestResponse requestResponse = result.getRequestResponse();
        String responseId = "result:" + selectedTaskMd5 + ":" + selectedRow;
        if (requestResponse != null && !responseId.equals(currentDisplayedResponseId)) {
            currentDisplayedResponseId = responseId;
            if (requestResponse.request() != null) {
                requestEditor.setRequest(requestResponse.request());
            }
            if (requestResponse.response() != null) {
                responseEditor.setResponse(requestResponse.response());
            }
        }
    }

    /**
     * 追加日志消息
     *
     * @param message 日志消息
     */
    public void appendLog(String message) {
        SwingUtilities.invokeLater(() -> {
            String currentText = logTextArea.getText();
            String newText;
            if (currentText.isEmpty()) {
                newText = message;
            } else {
                newText = currentText + "\n" + message;
            }
            // 限制日志最大长度为 50000 字符，超过则截取后半部分
            if (newText.length() > 50000) {
                int cutIndex = newText.indexOf("\n", newText.length() - 40000);
                if (cutIndex > 0) {
                    newText = newText.substring(cutIndex + 1);
                }
            }
            logTextArea.setText(newText);
            logTextArea.setCaretPosition(logTextArea.getDocument().getLength());
        });
    }

    // ==================== DataChangeListener 接口实现 ====================

    /**
     * 任务列表变更回调
     */
    @Override
    public void onTasksChanged() {
        taskTableModel.fireTableDataChanged();

        // 如果列表为空，清空选中状态和查看器
        if (taskTable.getRowCount() == 0) {
            selectedTaskMd5 = "";
            selectedTaskRow = -1;
            clearEditors();
        } else if (selectedTaskRow >= 0 && selectedTaskRow < taskTable.getRowCount()) {
            // 保持选中行，使用标志位避免触发编辑器更新
            isProgrammaticSelection = true;
            try {
                taskTable.setRowSelectionInterval(selectedTaskRow, selectedTaskRow);
            } finally {
                isProgrammaticSelection = false;
            }
        }
    }

    /**
     * 清空请求/响应查看器
     */
    private void clearEditors() {
        SwingUtilities.invokeLater(() -> {
            currentDisplayedResponseId = "";
            requestEditor.setRequest(HttpRequest.httpRequest(""));
            responseEditor.setResponse(HttpResponse.httpResponse(""));
        });
    }

    /**
     * 结果列表变更回调
     */
    @Override
    public void onResultsChanged() {
        int selectedRow = resultTable.getSelectedRow();
        resultTableModel.fireTableDataChanged();

        // 恢复选中行，使用标志位避免触发编辑器更新
        if (selectedRow >= 0 && selectedRow < resultTable.getRowCount()) {
            isProgrammaticSelection = true;
            try {
                resultTable.setRowSelectionInterval(selectedRow, selectedRow);
            } finally {
                isProgrammaticSelection = false;
            }
        }
    }

    /**
     * 日志消息回调
     */
    @Override
    public void onLogMessage(String message) {
        appendLog(message);
    }
}
