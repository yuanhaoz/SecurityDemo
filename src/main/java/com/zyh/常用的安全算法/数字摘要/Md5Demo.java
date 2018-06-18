package com.zyh.常用的安全算法.数字摘要;

import java.security.MessageDigest;

/**
 * @author yuanhao
 * @date 2018/6/16 16:44
 */
public class Md5Demo {

    public static void main(String[] args) throws Exception {
        byte[] bytes = testMD5("hello, i am world, good night!");

        // 十六进制编码转换
        System.out.println(HexCode.bytes2hex(bytes));
        // 32 * 4 = 128 位
        System.out.println(HexCode.bytes2hex(bytes).length());

        // Base64编码转换
        System.out.println(Base64Code.byte2base64(bytes));
        System.out.println(Base64Code.byte2base64(bytes).length());
    }

    public static byte[] testMD5(String content) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] bytes = md.digest(content.getBytes("utf8"));
        return bytes;
    }

}
