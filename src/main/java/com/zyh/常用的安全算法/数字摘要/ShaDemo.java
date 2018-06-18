package com.zyh.常用的安全算法.数字摘要;

import java.security.MessageDigest;

/**
 * @author yuanhao
 * @date 2018/6/16 17:03
 */
public class ShaDemo {

    public static void main(String[] args) throws Exception {
        byte[] bytes = testSHA1("hello, i am world, good night!");

        // 十六进制编码转换
        System.out.println(HexCode.bytes2hex(bytes));
        // 40 * 4 = 160 位
        System.out.println(HexCode.bytes2hex(bytes).length());

        // Base64编码转换
        System.out.println(Base64Code.byte2base64(bytes));
        System.out.println(Base64Code.byte2base64(bytes).length());
    }

    public static byte[] testSHA1(String content) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] bytes = md.digest(content.getBytes("utf8"));
        return bytes;
    }

}
