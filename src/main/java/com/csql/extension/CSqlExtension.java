package com.csql.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.csql.config.ScannerConfig;
import com.csql.scanner.SqlInjectionScanner;
import com.csql.ui.MainTab;

/**
 * C_SQL 插件主入口类
 *
 * 实现 BurpExtension 接口，这是 Montoya API 中插件的入口点
 * 当 Burp Suite 加载插件时，会调用 initialize 方法
 *
 * @author C_SQL Team
 * @version 2.0.0
 */
public class CSqlExtension implements BurpExtension {

    /**
     * 插件名称常量
     */
    public static final String EXTENSION_NAME = "C_SQL";

    /**
     * 插件版本号
     */
    public static final String VERSION = "3.0.0";

    /**
     * Montoya API 实例
     * 通过此对象可以访问 Burp Suite 的所有功能
     */
    private MontoyaApi api;

    /**
     * 日志记录器
     * 用于在 Burp Suite 的输出面板中打印日志
     */
    private Logging logging;

    /**
     * 扫描器配置
     * 存储所有扫描相关的配置选项
     */
    private ScannerConfig config;

    /**
     * SQL 注入扫描器
     * 负责执行实际的 SQL 注入检测逻辑
     */
    private SqlInjectionScanner scanner;

    /**
     * 主界面标签页
     * 显示在 Burp Suite 的主标签栏中
     */
    private MainTab mainTab;

    /**
     * 插件初始化方法
     *
     * 这是 Montoya API 的入口点，当 Burp Suite 加载插件时会自动调用此方法
     * 在此方法中完成所有初始化工作，包括：
     * 1. 保存 API 引用
     * 2. 设置插件名称
     * 3. 初始化配置
     * 4. 创建扫描器
     * 5. 构建 UI
     * 6. 注册各种处理器
     *
     * @param api Burp Suite 提供的 MontoyaApi 实例，通过它可以访问所有功能
     */
    @Override
    public void initialize(MontoyaApi api) {
        // 保存 API 引用，供其他组件使用
        this.api = api;

        // 获取日志记录器
        this.logging = api.logging();

        // 设置插件名称，会显示在 Burp Suite 的扩展列表中
        api.extension().setName(EXTENSION_NAME);

        // 初始化扫描器配置
        this.config = new ScannerConfig();

        // 创建 SQL 注入扫描器实例
        this.scanner = new SqlInjectionScanner(api, config);

        // 创建主界面标签页
        this.mainTab = new MainTab(api, config, scanner);

        // 注册 HTTP 请求/响应处理器
        // 当有 HTTP 流量经过 Burp 时，会触发扫描器的处理逻辑
        api.http().registerHttpHandler(scanner);

        // 注册右键菜单提供者
        // 允许用户在 Repeater 和 Proxy 中右键发送请求到 C_SQL
        api.userInterface().registerContextMenuItemsProvider(scanner);

        // 注册自定义标签页
        // 在 Burp Suite 主界面添加 C_SQL 标签页
        api.userInterface().registerSuiteTab(EXTENSION_NAME, mainTab.getComponent());

        // 打印加载成功信息
        logging.logToOutput(String.format("%s v%s 插件加载成功!", EXTENSION_NAME, VERSION));
        logging.logToOutput("=".repeat(50));
        logging.logToOutput("配置文件: " + ScannerConfig.getConfigFilePath());
        logging.logToOutput("=".repeat(50));
        logging.logToOutput("功能说明:");
        logging.logToOutput("  - 被动扫描: 自动检测经过 Proxy/Repeater 的请求");
        logging.logToOutput("  - 主动扫描: 右键选择 'Send to C_SQL' 手动触发");
        logging.logToOutput("  - 支持 GET/POST/JSON 参数的 SQL 注入检测");
        logging.logToOutput("  - 支持自定义 Payload 和报错关键词");
        logging.logToOutput("=".repeat(50));
    }

    /**
     * 获取 Montoya API 实例
     *
     * @return MontoyaApi 实例
     */
    public MontoyaApi getApi() {
        return api;
    }

    /**
     * 获取扫描器配置
     *
     * @return 扫描器配置对象
     */
    public ScannerConfig getConfig() {
        return config;
    }

    /**
     * 获取 SQL 注入扫描器
     *
     * @return 扫描器实例
     */
    public SqlInjectionScanner getScanner() {
        return scanner;
    }
}
