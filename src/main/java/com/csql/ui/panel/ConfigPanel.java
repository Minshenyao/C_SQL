package com.csql.ui.panel;

import com.csql.config.ScannerConfig;
import com.csql.extension.CSqlExtension;
import com.csql.scanner.SqlInjectionScanner;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.function.Consumer;

/**
 * 配置面板类
 *
 * 负责构建基础设置面板，包括：
 * - 插件开关
 * - 监控设置
 * - 域名过滤
 * - 请求延迟
 *
 * @author C_SQL Team
 * @version 2.0.0
 */
public class ConfigPanel {

    /**
     * 扫描器配置
     */
    private final ScannerConfig config;

    /**
     * SQL 注入扫描器
     */
    private final SqlInjectionScanner scanner;

    /**
     * 主面板组件
     */
    private final JPanel mainPanel;

    /**
     * 构造函数
     *
     * @param config      扫描器配置
     * @param scanner     SQL 注入扫描器
     * @param logCallback 日志回调函数（保留参数兼容性）
     */
    public ConfigPanel(ScannerConfig config, SqlInjectionScanner scanner, Consumer<String> logCallback) {
        this.config = config;
        this.scanner = scanner;
        this.mainPanel = buildPanel();
    }

    /**
     * 获取面板组件
     *
     * @return 面板组件
     */
    public JPanel getComponent() {
        return mainPanel;
    }

    /**
     * 构建配置面板
     *
     * @return 配置面板
     */
    private JPanel buildPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new EmptyBorder(8, 10, 8, 10));

        // 插件名称和版本（使用 GridLayout 均匀分布）
        JPanel infoPanel = new JPanel(new GridLayout(1, 2, 18, 0));
        infoPanel.add(new JLabel("插件名称: " + CSqlExtension.EXTENSION_NAME));
        infoPanel.add(new JLabel("插件版本: " + CSqlExtension.VERSION));
        infoPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        infoPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, infoPanel.getPreferredSize().height));

        // 插件开关按钮
        JButton toggleButton = new JButton(config.isPluginEnabled() ? "关闭插件" : "启动插件");
        JPanel togglePanel = new JPanel(new BorderLayout());
        togglePanel.add(toggleButton, BorderLayout.NORTH);
        togglePanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, togglePanel.getPreferredSize().height));
        togglePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        toggleButton.addActionListener(e -> {
            if (config.isPluginEnabled()) {
                config.setPluginEnabled(false);
                toggleButton.setText("启动插件");
            } else {
                config.setPluginEnabled(true);
                toggleButton.setText("关闭插件");
            }
        });

        // 监控设置复选框
        JCheckBox monitorProxyCheckbox = new JCheckBox("监控Proxy", config.isMonitorProxy());
        JCheckBox monitorRepeaterCheckbox = new JCheckBox("监控Repeater", config.isMonitorRepeater());
        JCheckBox numericParamsCheckbox = new JCheckBox("值是数字则进行-1、-0", config.isTestNumericParams());
        JCheckBox testCookieCheckbox = new JCheckBox("测试Cookie", config.isTestCookieParams());

        JPanel switchesGrid = new JPanel(new GridLayout(2, 2, 18, 6));
        switchesGrid.add(monitorProxyCheckbox);
        switchesGrid.add(monitorRepeaterCheckbox);
        switchesGrid.add(numericParamsCheckbox);
        switchesGrid.add(testCookieCheckbox);
        switchesGrid.setMaximumSize(new Dimension(Integer.MAX_VALUE, switchesGrid.getPreferredSize().height));
        switchesGrid.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 复选框事件监听
        monitorProxyCheckbox.addItemListener(e -> {
            config.setMonitorProxy(monitorProxyCheckbox.isSelected());
        });

        monitorRepeaterCheckbox.addItemListener(e -> {
            config.setMonitorRepeater(monitorRepeaterCheckbox.isSelected());
        });

        numericParamsCheckbox.addItemListener(e -> {
            config.setTestNumericParams(numericParamsCheckbox.isSelected());
        });

        testCookieCheckbox.addItemListener(e -> {
            config.setTestCookieParams(testCookieCheckbox.isSelected());
        });

        // 清空列表按钮
        JButton clearButton = new JButton("清空列表");
        JPanel clearPanel = new JPanel(new BorderLayout());
        clearPanel.add(clearButton, BorderLayout.NORTH);
        clearPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, clearPanel.getPreferredSize().height));
        clearPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        clearButton.addActionListener(e -> {
            scanner.clearAll();
        });

        // 域名过滤设置
        JLabel filterLabel = new JLabel("域名过滤：白名单/黑名单二选一，多个用,隔开");
        filterLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        filterLabel.setMaximumSize(new Dimension(Integer.MAX_VALUE, filterLabel.getPreferredSize().height));

        JTextField domainTextField = new JTextField("填写白/黑名单域名");
        Dimension fixedSize = new Dimension(350, domainTextField.getPreferredSize().height);
        domainTextField.setPreferredSize(fixedSize);
        domainTextField.setMaximumSize(fixedSize);
        domainTextField.setMinimumSize(fixedSize);
        domainTextField.setAlignmentX(Component.LEFT_ALIGNMENT);

        JButton whitelistButton = new JButton("启动白名单");
        JButton blacklistButton = new JButton("启动黑名单");
        JPanel listModePanel = new JPanel(new GridLayout(1, 2, 18, 0));
        listModePanel.add(whitelistButton);
        listModePanel.add(blacklistButton);
        listModePanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, listModePanel.getPreferredSize().height));
        listModePanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 白名单按钮事件
        whitelistButton.addActionListener(e -> {
            if (whitelistButton.getText().equals("启动白名单")) {
                whitelistButton.setText("关闭白名单");
                config.setWhitelistUrls(domainTextField.getText());
                config.setWhitelistEnabled(true);

                // 关闭黑名单
                if (config.isBlacklistEnabled()) {
                    config.setBlacklistEnabled(false);
                    blacklistButton.setText("启动黑名单");
                }

                domainTextField.setEditable(false);
                domainTextField.setForeground(Color.GRAY);
            } else {
                whitelistButton.setText("启动白名单");
                config.setWhitelistEnabled(false);

                if (!config.isBlacklistEnabled()) {
                    domainTextField.setEditable(true);
                    domainTextField.setForeground(Color.BLACK);
                }
            }
        });

        // 黑名单按钮事件
        blacklistButton.addActionListener(e -> {
            if (blacklistButton.getText().equals("启动黑名单")) {
                blacklistButton.setText("关闭黑名单");
                config.setBlacklistUrls(domainTextField.getText());
                config.setBlacklistEnabled(true);

                // 关闭白名单
                if (config.isWhitelistEnabled()) {
                    config.setWhitelistEnabled(false);
                    whitelistButton.setText("启动白名单");
                }

                domainTextField.setEditable(false);
                domainTextField.setForeground(Color.GRAY);
            } else {
                blacklistButton.setText("启动黑名单");
                config.setBlacklistEnabled(false);

                if (!config.isWhitelistEnabled()) {
                    domainTextField.setEditable(true);
                    domainTextField.setForeground(Color.BLACK);
                }
            }
        });

        // 请求延迟设置
        JLabel delayLabel = new JLabel("发包延时(ms)：");
        delayLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextField delayTextField = new JTextField(String.valueOf(config.getRequestDelayMs()), 6);
        JButton delayButton = new JButton(config.getRequestDelayMs() > 0 ? "取消延时" : "应用延时");

        JPanel delayPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        delayPanel.add(delayLabel);
        delayPanel.add(delayTextField);
        delayPanel.add(delayButton);
        delayPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, delayPanel.getPreferredSize().height));
        delayPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        // 更新延迟 UI 的 Runnable
        Runnable updateDelayUi = () -> {
            if (config.getRequestDelayMs() > 0) {
                delayButton.setText("取消延时");
                delayTextField.setEditable(false);
                delayTextField.setForeground(Color.GRAY);
            } else {
                delayButton.setText("应用延时");
                delayTextField.setEditable(true);
                delayTextField.setForeground(Color.BLACK);
            }
        };

        // 延迟按钮事件
        delayButton.addActionListener(e -> {
            if (config.getRequestDelayMs() > 0) {
                config.setRequestDelayMs(0);
                delayTextField.setText("0");
            } else {
                try {
                    int delay = Integer.parseInt(delayTextField.getText().trim());
                    config.setRequestDelayMs(delay);
                } catch (NumberFormatException ex) {
                    config.setRequestDelayMs(0);
                }
            }
            updateDelayUi.run();
        });

        // 延迟文本框回车事件
        delayTextField.addActionListener(e -> {
            try {
                int delay = Integer.parseInt(delayTextField.getText().trim());
                config.setRequestDelayMs(delay);
            } catch (NumberFormatException ex) {
                config.setRequestDelayMs(0);
            }
            updateDelayUi.run();
        });

        // 初始化延迟 UI 状态
        updateDelayUi.run();

        // 组装面板
        panel.add(infoPanel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(togglePanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(switchesGrid);
        panel.add(Box.createVerticalStrut(10));
        panel.add(clearPanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(filterLabel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(domainTextField);
        panel.add(Box.createVerticalStrut(5));
        panel.add(listModePanel);
        panel.add(Box.createVerticalStrut(10));
        panel.add(delayPanel);

        return panel;
    }
}
