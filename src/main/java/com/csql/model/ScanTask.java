package com.csql.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URL;

/**
 * 扫描任务实体类
 *
 * 表示一个扫描任务，包含原始请求的信息和扫描状态
 * 每当有新的 HTTP 请求需要扫描时，会创建一个 ScanTask 实例
 *
 * @author C_SQL Team
 * @version 2.0.0
 */
public class ScanTask {

    /**
     * 任务 ID，用于唯一标识每个扫描任务
     */
    private final int id;

    /**
     * 请求来源工具名称
     * 如：Proxy、Repeater、Extension 等
     */
    private final String toolSource;

    /**
     * HTTP 请求响应对象
     * 包含完整的请求和响应数据
     */
    private final HttpRequestResponse requestResponse;

    /**
     * 请求的 URL
     */
    private final String url;

    /**
     * 原始响应包长度
     * 用于后续比较响应长度变化
     */
    private final int originalResponseLength;

    /**
     * 请求的 MD5 哈希值
     * 用于去重，避免重复扫描相同的请求
     */
    private final String requestMd5;

    /**
     * 扫描状态
     * 如：run...... 、end!、end! ✔ 等
     */
    private volatile String state;

    /**
     * 构造函数
     *
     * @param id                     任务 ID
     * @param toolSource             请求来源工具
     * @param requestResponse        HTTP 请求响应对象
     * @param url                    请求 URL
     * @param originalResponseLength 原始响应长度
     * @param requestMd5             请求 MD5
     */
    public ScanTask(int id, String toolSource, HttpRequestResponse requestResponse,
                    String url, int originalResponseLength, String requestMd5) {
        this.id = id;
        this.toolSource = toolSource;
        this.requestResponse = requestResponse;
        this.url = url;
        this.originalResponseLength = originalResponseLength;
        this.requestMd5 = requestMd5;
        this.state = "run......";
    }

    // ==================== Getter 方法 ====================

    public int getId() {
        return id;
    }

    public String getToolSource() {
        return toolSource;
    }

    public HttpRequestResponse getRequestResponse() {
        return requestResponse;
    }

    public String getUrl() {
        return url;
    }

    public int getOriginalResponseLength() {
        return originalResponseLength;
    }

    public String getRequestMd5() {
        return requestMd5;
    }

    public String getState() {
        return state;
    }

    /**
     * 设置扫描状态
     *
     * @param state 新的状态字符串
     */
    public void setState(String state) {
        this.state = state;
    }

    /**
     * 获取响应长度
     * 如果响应为空则返回 0
     *
     * @return 响应长度
     */
    public int getResponseLength() {
        if (requestResponse != null && requestResponse.response() != null) {
            return requestResponse.response().toByteArray().length();
        }
        return 0;
    }
}
