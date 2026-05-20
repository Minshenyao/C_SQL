package com.csql.ui.table;

import com.csql.model.ScanResult;
import com.csql.scanner.SqlInjectionScanner;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * 结果表格数据模型
 *
 * 负责为结果表格提供数据
 * 显示每个参数测试的详细结果，包括：
 * - 参数名
 * - Payload
 * - 响应长度
 * - 变化标记
 * - 响应时间
 * - 响应状态码
 *
 * @author C_SQL Team
 * @version 2.0.0
 */
public class ResultTableModel extends AbstractTableModel {

    /**
     * SQL 注入扫描器（数据源）
     */
    private final SqlInjectionScanner scanner;

    /**
     * 当前显示的任务 MD5
     * 只显示属于该任务的结果
     */
    private String currentTaskMd5 = "";

    /**
     * 列名数组
     */
    private static final String[] COLUMN_NAMES = {
            "参数",        // 测试的参数名
            "payload",     // 参数值 + Payload
            "返回包长度",   // 响应长度
            "变化",        // 变化标记
            "用时",        // 响应时间（毫秒）
            "响应码"       // HTTP 状态码
    };

    /**
     * 构造函数
     *
     * @param scanner SQL 注入扫描器
     */
    public ResultTableModel(SqlInjectionScanner scanner) {
        this.scanner = scanner;
    }

    /**
     * 设置当前任务 MD5
     * 用于筛选显示的结果
     *
     * @param taskMd5 任务 MD5
     */
    public void setCurrentTaskMd5(String taskMd5) {
        this.currentTaskMd5 = taskMd5;
    }

    /**
     * 获取当前任务的结果列表
     *
     * @return 结果列表
     */
    private List<ScanResult> getCurrentResults() {
        return scanner.getResultsByTaskMd5(currentTaskMd5);
    }

    /**
     * 获取行数
     *
     * @return 结果数量
     */
    @Override
    public int getRowCount() {
        return getCurrentResults().size();
    }

    /**
     * 获取列数
     *
     * @return 列数量
     */
    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    /**
     * 获取列名
     *
     * @param column 列索引
     * @return 列名称
     */
    @Override
    public String getColumnName(int column) {
        if (column >= 0 && column < COLUMN_NAMES.length) {
            return COLUMN_NAMES[column];
        }
        return "";
    }

    /**
     * 获取列类型
     *
     * @param columnIndex 列索引
     * @return 列数据类型
     */
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        // 所有列都以字符串形式显示
        return String.class;
    }

    /**
     * 获取单元格值
     *
     * @param rowIndex    行索引
     * @param columnIndex 列索引
     * @return 单元格值
     */
    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        List<ScanResult> results = getCurrentResults();

        // 检查行索引有效性
        if (rowIndex < 0 || rowIndex >= results.size()) {
            return "";
        }

        ScanResult result = results.get(rowIndex);

        // 根据列索引返回相应数据
        return switch (columnIndex) {
            case 0 -> result.getParameter();           // 参数名
            case 1 -> result.getPayload();             // Payload
            case 2 -> result.getResponseLength();      // 响应长度
            case 3 -> result.getChangeMarker();        // 变化标记
            case 4 -> result.getResponseTime();        // 响应时间
            case 5 -> result.getResponseCode();        // 响应状态码
            default -> "";
        };
    }

    /**
     * 单元格是否可编辑
     * 所有单元格都不可编辑
     *
     * @param rowIndex    行索引
     * @param columnIndex 列索引
     * @return false（不可编辑）
     */
    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return false;
    }
}
