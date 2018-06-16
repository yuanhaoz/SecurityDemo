package com.zyh.数字摘要;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

/**
 * 基于 Java 的 Base64 算法的使用
 * @author yuanhao
 * @date 2018/6/16 18:25
 */
public class Base64Code {

    /**
     * 将二进制数据进行Base64编码表示
     * @param bytes 二进制数据
     * @return Base64编码
     */
    public static String byte2base64(byte[] bytes) {
        BASE64Encoder base64Encoder = new BASE64Encoder();
        return base64Encoder.encode(bytes);
    }

    /**
     * 将Base64编码数据解码为二进制数据
     * @param base64 Base64编码数据
     * @return 二进制数据
     * @throws IOException IO异常
     */
    public static byte[] base642byte(String base64) throws IOException {
        BASE64Decoder base64Decoder = new BASE64Decoder();
        return base64Decoder.decodeBuffer(base64);
    }
}
