package com.csql.ui.table;

import com.csql.model.ScanTask;
import com.csql.scanner.SqlInjectionScanner;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * 任务表格数据模型
 *
 * 负责为任务表格提供数据
 * 显示扫描任务的基本信息，包括：
 * - 任务 ID
 * - 请求来源
 * - URL
 * - 响应长度
 * - 扫描状态
 *
 * @author C_SQL Team
 * @version 2.0.0
 */
public class TaskTableModel extends AbstractTableModel {

    /**
     * SQL 注入扫描器（数据源）
     */
    private final SqlInjectionScanner scanner;

    /**
     * 列名数组
     */
    private static final String[] COLUMN_NAMES = {
            "#",           // 任务 ID
            "来源",        // 请求来源工具
            "URL",         // 请求 URL
            "返回包长度",   // 原始响应长度
            "状态"         // 扫描状态
    };

    /**
     * 构造函数
     *
     * @param scanner SQL 注入扫描器
     */
    public TaskTableModel(SqlInjectionScanner scanner) {
        this.scanner = scanner;
    }

    /**
     * 获取行数
     *
     * @return 任务数量
     */
    @Override
    public int getRowCount() {
        return scanner.getScanTasks().size();
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
        List<ScanTask> tasks = scanner.getScanTasks();

        // 检查行索引有效性
        if (rowIndex < 0 || rowIndex >= tasks.size()) {
            return "";
        }

        ScanTask task = tasks.get(rowIndex);

        // 根据列索引返回相应数据
        return switch (columnIndex) {
            case 0 -> task.getId();                    // 任务 ID
            case 1 -> task.getToolSource();            // 请求来源
            case 2 -> task.getUrl();                   // URL
            case 3 -> task.getResponseLength();        // 响应长度
            case 4 -> task.getState();                 // 扫描状态
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
