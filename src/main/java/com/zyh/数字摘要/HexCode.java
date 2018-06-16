package com.zyh.数字摘要;

/**
 * 基于 Java 的十六进制编码与解码的实现。
 * @author yuanhao
 * @date 2018/6/16 17:11
 */
public class HexCode {

    /**
     * 将二进制数据编码为十六进制编码表示
     * @param bytes 二进制数据
     * @return 十六进制编码
     */
    public static String bytes2hex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            byte b = bytes[i];
            // 是否为负数
            boolean negative = false;
            if (b < 0) {
                negative = true;
            }
            int inte = Math.abs(b);
            if (negative) {
                // 负数会转成正数（最高位的负号变成数值计算），再转十六进制
                inte = inte | 0x80;
            }
            String temp = Integer.toHexString(inte & 0xFF);
            if (temp.length() == 1) {
                hex.append("0");
            }
            hex.append(temp.toLowerCase());
        }
        return hex.toString();
    }

    /**
     * 将十六进制数据解码为二进制数据
     * @param hex 十六进制编码数据
     * @return 二进制数据
     */
    private static byte[] hex2bytes(String hex) {
        byte[] bytes = new byte[hex.length()/2];
        for (int i = 0; i < hex.length(); i = i + 2) {
            String subStr = hex.substring(i, i + 2);
            // 是否为负数
            boolean negative = false;
            int inte = Integer.parseInt(subStr, 16);
            if (inte > 127) {
                negative = true;
            }
            if (inte == 128) {
                inte = -128;
            } else if (negative) {
                inte = 0 - (inte & 0x7F);
            }
            byte b = (byte) inte;
            bytes[i/2] = b;
        }
        return bytes;
    }

}
