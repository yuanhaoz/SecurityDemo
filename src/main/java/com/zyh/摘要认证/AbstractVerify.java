package com.zyh.摘要认证;

import com.zyh.常用的安全算法.数字摘要.Base64Code;

import java.security.MessageDigest;
import java.util.*;

/**
 * 摘要认证的实现
 * 摘要认证这种方式可以在一定程度上保障通信的安全，防止通信过程中数据被第三方篡改。
 * 实现起来主要包含如下四个方面：客户端参数摘要生成、服务端参数摘要校验、
 * 服务端相应摘要生成和客户端相应摘要校验。
 *
 * @author yuanhao
 * @date 2018/6/18 15:14
 */
public class AbstractVerify {

    public static void main(String[] args) throws Exception {
        Map<String, String> params = new HashMap<String, String>();
        params.put("headers", "hello");
        params.put("Cookies", "hello world");
        params.put("Agent", "hello world zheng yuanhao");
        // 客户端参数摘要生成
        String str = getDigest(params);
        System.out.println(str);
        // 服务端参数摘要校验
        System.out.println(validate(params, str));
        // 服务端响应摘要生成
        String content = "hello world, 2018-6-18!";
        String responseBase64 = getDigest(content);
        System.out.println(responseBase64);
        // 客户端响应摘要校验
        System.out.println(validate(content, responseBase64));
    }

    // 约定的 secret
    private static final String secret = "abcdefjhijklmn";

    /**
     * 摘要生成算法
     * @param str 待摘要的字符串
     * @return 摘要结果
     * @throws Exception 异常
     */
    private static byte[] getMD5base64(String str) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] bytes = md.digest(str.getBytes("utf8"));
        return bytes;
    }

    /**
     * 基于 Java 客户端参数摘要生成的部分关键代码
     * @param params 客户端参数
     * @return 客户端参数摘要
     * @throws Exception 异常
     */
    private static String getDigest(Map<String, String> params) throws Exception {
        Set<String> keySet = params.keySet();
        // 对客户端请求的参数先排好序：使用 treeset 排序
        TreeSet<String> sortSet = new TreeSet<String>();
        sortSet.addAll(keySet);
        // 将参数名称和参数值串起来，机上约定好的 secret，生成待摘要的字符串
        String keyvalueStr = "";
        Iterator<String> it = sortSet.iterator();
        while (it.hasNext()) {
            String key = it.next();
            String value = params.get(key);
            keyvalueStr += key + value;
        }
        keyvalueStr += secret;
        // 使用 MD5摘要算法生成摘要串
        String base64Str = Base64Code.byte2base64(getMD5base64(keyvalueStr));
        return base64Str;
    }

    /**
     * 基于 Java 服务端参数摘要检验的部分关键代码
     * @param params 客户端参数
     * @param digest 客户端参数摘要
     * @return 是否篡改
     * @throws Exception 异常
     */
    private static Boolean validate(Map params, String digest) throws Exception {
        Set<String> keySet = params.keySet();
        // 对客户端请求的参数先排好序：使用 treeset 排序
        TreeSet<String> sortSet = new TreeSet<String>();
        sortSet.addAll(keySet);
        // 将参数名称和参数值串起来，加上约定好的 secret，生成待摘要的字符串
        String keyvalueStr = "";
        Iterator<String> it = sortSet.iterator();
        while (it.hasNext()) {
            String key = it.next();
            String values = (String) params.get(key);
            keyvalueStr += key + values;
        }
        keyvalueStr += secret;
        // 使用 MD5摘要算法生成摘要串
        String base64Str = Base64Code.byte2base64(getMD5base64(keyvalueStr));
        // 服务端接收到请求的参数后，计算出摘要，
        // 与客户端通过header或其他形式传递的摘要串对比，便可得知消息是否被篡改
        if (base64Str.equals(digest)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 基于 Java 服务端响应摘要生成的部分关键代码
     * @param content 服务端响应的 JSON 数据或者 HTML 文本数据
     * @return 响应摘要
     * @throws Exception 异常
     */
    private static String getDigest(String content) throws Exception {
        // 加上约定好的 secret，生成待摘要的字符串
        content += secret;
        // 使用 MD5摘要算法生成摘要串，使用 Base64 对摘要数据进行编码
        String base64Str = Base64Code.byte2base64(getMD5base64(content));
        return base64Str;
    }

    /**
     * 基于 Java 客户端响应摘要校验的部分关键代码
     * @param responseContent 客户端收到的服务端响应
     * @param digest 服务端通过 header 等方式传递过来的摘要信息
     * @return 服务端响应是否被篡改
     * @throws Exception
     */
    private static boolean validate(String responseContent, String digest) throws Exception {
        byte[] bytes = getMD5base64(responseContent + secret);
        String responseDigest = Base64Code.byte2base64(bytes);
        if (responseDigest.equals(digest)) {
            return true;
        } else {
            return false;
        }
    }

}
