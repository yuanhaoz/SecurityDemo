package com.zyh.常用的安全算法.数字签名;

import com.zyh.常用的安全算法.数字摘要.Base64Code;
import com.zyh.常用的安全算法.非对称加密算法.RsaDemo;

import java.security.*;

/**
 * MD5withRSA 算法的实现。
 * @author yuanhao
 * @date 2018/6/16 16:25
 */
public class Sha1withRsaDemo {

    public static void main(String[] args) throws Exception {
        String str = "hello, i am world, good night!";
        System.out.println("明文的Base64编码为：" + Base64Code.byte2base64(str.getBytes()));
        System.out.println();

        KeyPair keyPair = RsaDemo.getKeyPair();
        String publicKeyBase64 = RsaDemo.getPublicKey(keyPair);
        System.out.println("公钥为：" + publicKeyBase64);
        String privateKeyBase64 = RsaDemo.getPrivateKey(keyPair);
        System.out.println("私钥为：" + privateKeyBase64);
        System.out.println();
        PublicKey publicKey = RsaDemo.string2PublicKey(publicKeyBase64);
        PrivateKey privateKey = RsaDemo.string2PrivateKey(privateKeyBase64);

        // 基于 Java 实现数字签名算法
        byte[] rsaEncrypt = sign(str.getBytes(), privateKey);
        System.out.println("公钥加密后得到密文的Base64编码为：" + Base64Code.byte2base64(rsaEncrypt));
        boolean flag = verify(str.getBytes(), rsaEncrypt, publicKey);
        System.out.println("是否一致：" + flag);

    }

    /**
     * 基于 Java 的 Signature API 的使用
     * @param content 待加密的数据
     * @param privateKey 私钥
     * @return 密文
     * @throws Exception 异常
     */
    private static byte[] sign(byte[] content, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        // 调用 update 传入签名内容
        signature.update(content);
        return signature.sign();
    }

    /**
     * 基于 Java 实现数字签名算法
     * @param content 待加密的数据
     * @param sign 加密的密文
     * @param publicKey 公钥
     * @return 是否正确
     * @throws Exception 异常
     */
    private static boolean verify(byte[] content, byte[] sign, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(publicKey);
        // 调用 update 传入需要校验的内容
        signature.update(content);
        return signature.verify(sign);
    }



}
