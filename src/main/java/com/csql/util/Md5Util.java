package com.csql.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD5 工具类
 *
 * 用于计算字符串的 MD5 哈希值
 * 主要用于请求去重，避免重复扫描相同的请求
 *
 * @author C_SQL Team
 * @version 2.0.0
 */
public class Md5Util {

    /**
     * 十六进制字符数组
     * 用于将字节转换为十六进制字符串
     */
    private static final char[] HEX_CHARS = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    /**
     * 私有构造函数，防止实例化
     */
    private Md5Util() {
        // 工具类不允许实例化
    }

    /**
     * 计算字符串的 MD5 哈希值
     *
     * @param input 输入字符串
     * @return MD5 哈希值（大写十六进制字符串），如果计算失败则返回 null
     */
    public static String md5(String input) {
        if (input == null) {
            return null;
        }

        try {
            // 获取 MD5 消息摘要实例
            MessageDigest md5 = MessageDigest.getInstance("MD5");

            // 计算摘要
            byte[] digest = md5.digest(input.getBytes());

            // 将字节数组转换为十六进制字符串
            return bytesToHex(digest);

        } catch (NoSuchAlgorithmException e) {
            // MD5 算法应该始终可用，这种情况不应该发生
            return null;
        }
    }

    /**
     * 将字节数组转换为十六进制字符串
     *
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        int index = 0;

        for (byte b : bytes) {
            // 高 4 位
            hexChars[index++] = HEX_CHARS[(b >>> 4) & 0x0F];
            // 低 4 位
            hexChars[index++] = HEX_CHARS[b & 0x0F];
        }

        return new String(hexChars);
    }
}
