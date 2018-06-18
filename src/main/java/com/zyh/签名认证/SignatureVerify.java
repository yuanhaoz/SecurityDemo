package com.zyh.签名认证;

import com.zyh.常用的安全算法.数字摘要.Base64Code;
import com.zyh.常用的安全算法.数字摘要.HexCode;
import com.zyh.常用的安全算法.非对称加密算法.RsaDemo;

import java.security.*;
import java.util.*;

/**
 * 签名认证的实现
 * 相较于摘要认证方式，签名认证的方式能够更好地保障通信的安全，防止通信过程中数据被第三方篡改。
 * 实现起来主要包含如下四个方面：客户端参数签名生成、服务端参数签名校验、服务端相应签名生成和客户端相应签名校验。
 * @author yuanhao
 * @date 2018/6/18 16:36
 */
public class SignatureVerify {

    public static void main(String[] args) throws Exception {
        keyPair = RsaDemo.getKeyPair();
        publicKeyBase64 = RsaDemo.getPublicKey(keyPair);
        privateKeyBase64 = RsaDemo.getPrivateKey(keyPair);


        Map<String, String> params = new HashMap<String, String>();
        params.put("headers", "hello");
        params.put("Cookies", "hello world");
        params.put("Agent", "hello world zheng yuanhao");
        // 客户端参数摘要生成
        String str = getSign(params);
        System.out.println(str);
//        String str2 = getSign2(params);
//        System.out.println(str2);
        // 服务端参数摘要校验
        System.out.println(validate(params, str));
//        // 服务端响应摘要生成
//        String content = "hello world, 2018-6-18!";
//        String responseBase64 = getDigest(content);
//        System.out.println(responseBase64);
//        // 客户端响应摘要校验
//        System.out.println(validate(content, responseBase64));
    }

    /**
     * 非对称加密算法需要的  公钥和私钥对
     */
    private static KeyPair keyPair = null;
    private static String publicKeyBase64 = "";
    private static String privateKeyBase64 = "";

    /**
     * 摘要生成算法
     * @param str 待摘要的字符串
     * @return 摘要结果
     * @throws Exception 异常
     */
    private static byte[] getMD5(String str) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] bytes = md.digest(str.getBytes("utf8"));
        return bytes;
    }

    /**
     * 客户端参数签名生成
     * 基于 Java 客户端请求数字签名生成的部分关键代码
     * @param params 客户端参数
     * @return 客户端参数的数字签名
     * @throws Exception 异常
     */
    private static String getSign(Map<String, String> params) throws Exception {
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
        // 使用 MD5摘要算法生成摘要串
        byte[] md5Bytes = getMD5(keyvalueStr);
        // 得到私钥
        PrivateKey privateKey = RsaDemo.string2PrivateKey(privateKeyBase64);
        // 利用私钥对摘要串加密
        byte[] encryptBytes = RsaDemo.privateEncrypt(md5Bytes, privateKey);
        // 得到密文的 hex 编码
        String hexStr = HexCode.bytes2hex(encryptBytes);
        return hexStr;
    }

    /**
     * 客户端参数签名生成
     * 使用 Java 数字签名API对客户端请求进行数字签名
     * @param params 客户端参数
     * @return 客户端参数的数字签名
     * @throws Exception 异常
     */
    private static String getSign2(Map<String, String> params) throws Exception {
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
        // 得到私钥
        PrivateKey privateKey = RsaDemo.string2PrivateKey(privateKeyBase64);
        // Java 的 java.security.Signature 对数字签名的支持也非常出色，通过 getInstance 方法取得 MD5withRSA 的实例
        // 即通过MD5进行数字摘要，并且使用RSA算法进行非对称加密
        Signature signature = Signature.getInstance("MD5withRSA");
        // 使用客户端私钥对 signature 进行初始化
        signature.initSign(privateKey);
        // update 方法传入待摘要串
        signature.update(keyvalueStr.getBytes());
        // 通过 sign 方法即可取得对应内容的数字签名
        return HexCode.bytes2hex(signature.sign());
    }

    /**
     * 服务端参数签名校验
     * 基于 Java 服务端对客户端数字签名校验的部分关键代码
     * @param params 客户端参数
     * @param sign 客户端参数的数字签名
     * @return 是否篡改
     * @throws Exception 异常
     */
    private static Boolean validate(Map params, String sign) throws Exception {
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
        // 使用 MD5 摘要算法生成摘要串，得到摘要串的 hex 编码
        String hexStr = HexCode.bytes2hex(getMD5(keyvalueStr));

        // 得到公钥
        PublicKey publicKey = RsaDemo.string2PublicKey(publicKeyBase64);
        // 利用公钥对加密摘要串进行解密
        byte[] decryptBytes = RsaDemo.publicDecrypt(HexCode.hex2bytes(sign), publicKey);
        String decryptDigest = HexCode.bytes2hex(decryptBytes);

        // 服务端接收到请求的参数后，计算出摘要，
        // 与客户端通过header或其他形式传递的摘要串对比，便可得知消息是否被篡改
        if (hexStr.equals(decryptDigest)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 服务端参数签名校验
     * 使用 Java 数字签名API对客户端进行数字签名校验
     * @param params 客户端参数
     * @param sign 客户端参数的数字签名
     * @return 是否篡改
     * @throws Exception 异常
     */
    private static Boolean validate2(Map params, String sign) throws Exception {
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

        // 得到公钥
        PublicKey publicKey = RsaDemo.string2PublicKey(publicKeyBase64);
        // Java 的 java.security.Signature 对数字签名的支持也非常出色，通过 getInstance 方法取得 MD5withRSA 的实例
        // 即通过MD5进行数字摘要，并且使用RSA算法进行非对称加密
        Signature signature = Signature.getInstance("MD5withRSA");
        // 使用客户端私钥对 signature 进行初始化
        signature.initVerify(publicKey);
        // update 方法传入待摘要串
        signature.update(keyvalueStr.getBytes());
        // 通过 sign 方法即可取得对应内容的数字签名
        return signature.verify(HexCode.hex2bytes(sign));
    }

    /**
     * 服务端响应签名生成
     * 基于 Java 服务端响应数字签名生成的部分关键代码
     * @param content 服务端响应的 JSON 数据或者 HTML 文本数据
     * @return 响应数字签名
     * @throws Exception 异常
     */
    private static String getSign(String content) throws Exception {
        // 使用 MD5摘要算法生成摘要串
        byte[] md5Bytes = getMD5(content);
        // 得到私钥
        PrivateKey privateKey = RsaDemo.string2PrivateKey(privateKeyBase64);
        // 利用私钥对摘要串加密
        byte[] encryptBytes = RsaDemo.privateEncrypt(md5Bytes, privateKey);
        // 得到密文的 hex 编码
        String hexStr = HexCode.bytes2hex(encryptBytes);
        return hexStr;
    }

    /**
     * 服务端响应签名生成
     * 使用 Java 数字签名API生成服务端响应的数字签名
     * @param content 服务端响应的 JSON 数据或者 HTML 文本数据
     * @return 响应数字签名
     * @throws Exception 异常
     */
    private static String getSign2(String content) throws Exception {
        // 得到私钥
        PrivateKey privateKey = RsaDemo.string2PrivateKey(privateKeyBase64);
        // Java 的 java.security.Signature 对数字签名的支持也非常出色，通过 getInstance 方法取得 MD5withRSA 的实例
        // 即通过MD5进行数字摘要，并且使用RSA算法进行非对称加密
        Signature signature = Signature.getInstance("MD5withRSA");
        // 使用客户端私钥对 signature 进行初始化
        signature.initSign(privateKey);
        // update 方法传入待摘要串
        signature.update(content.getBytes());
        // 通过 sign 方法即可取得对应内容的数字签名
        return HexCode.bytes2hex(signature.sign());
    }

    /**
     * 客户端响应签名校验
     * 客户端对服务端响应数字签名校验的部分关键代码
     * @param responseContent 客户端收到的服务端响应
     * @param sign 服务端通过 header 等方式传递过来的数字签名信息
     * @return 服务端响应是否被篡改
     * @throws Exception
     */
    private static boolean validate(String responseContent, String sign) throws Exception {
        // 使用 MD5 摘要算法生成摘要串，得到摘要串的 hex 编码
        String hexStr = HexCode.bytes2hex(getMD5(responseContent));

        // 得到公钥
        PublicKey publicKey = RsaDemo.string2PublicKey(publicKeyBase64);
        // 利用公钥对加密摘要串进行解密
        byte[] decryptBytes = RsaDemo.publicDecrypt(HexCode.hex2bytes(sign), publicKey);
        String decryptDigest = HexCode.bytes2hex(decryptBytes);

        // 服务端接收到请求的参数后，计算出摘要，
        // 与客户端通过header或其他形式传递的摘要串对比，便可得知消息是否被篡改
        if (hexStr.equals(decryptDigest)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * 客户端响应签名校验
     * 使用 Java 数字签名API生成服务端响应的数字签名
     * @param responseContent 客户端收到的服务端响应
     * @param sign 服务端通过 header 等方式传递过来的数字签名信息
     * @return 服务端响应是否被篡改
     * @throws Exception
     */
    private static boolean validate2(String responseContent, String sign) throws Exception {
        // 得到公钥
        PublicKey publicKey = RsaDemo.string2PublicKey(publicKeyBase64);
        // Java 的 java.security.Signature 对数字签名的支持也非常出色，通过 getInstance 方法取得 MD5withRSA 的实例
        // 即通过MD5进行数字摘要，并且使用RSA算法进行非对称加密
        Signature signature = Signature.getInstance("MD5withRSA");
        // 使用客户端私钥对 signature 进行初始化
        signature.initVerify(publicKey);
        // update 方法传入待摘要串
        signature.update(responseContent.getBytes());
        // 通过 sign 方法即可取得对应内容的数字签名
        return signature.verify(HexCode.hex2bytes(sign));
    }

}
