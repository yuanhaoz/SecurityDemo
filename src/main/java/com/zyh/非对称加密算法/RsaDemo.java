package com.zyh.非对称加密算法;

import com.zyh.数字摘要.Base64Code;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 基于 Java 的 RSA 算法的使用。
 * @author yuanhao
 * @date 2018/6/16 16:25
 */
public class RsaDemo {

    public static void main(String[] args) throws Exception {
        String str = "hello, i am world, good night!";
        System.out.println("明文的Base64编码为：" + Base64Code.byte2base64(str.getBytes()));
        System.out.println();

        KeyPair keyPair = getKeyPair();
        String publicKeyBase64 = getPublicKey(keyPair);
        System.out.println("公钥为：" + publicKeyBase64);
        String privateKeyBase64 = getPrivateKey(keyPair);
        System.out.println("私钥为：" + privateKeyBase64);
        System.out.println();

        PublicKey publicKey = string2PublicKey(publicKeyBase64);
        PrivateKey privateKey = string2PrivateKey(privateKeyBase64);
        byte[] rsaEncrypt = publicEncrypt(str.getBytes(), publicKey);
        System.out.println("公钥加密后得到密文的Base64编码为：" + Base64Code.byte2base64(rsaEncrypt));
        byte[] rsaDecrypt = privateDecrypt(rsaEncrypt, privateKey);
        System.out.println("私钥解密后得到密文的Base64编码为：" + Base64Code.byte2base64(rsaDecrypt));
        System.out.println("私钥解密后得到密文的Base64编码与原明文是否相同：" + Base64Code.byte2base64(rsaDecrypt).equalsIgnoreCase(Base64Code.byte2base64(str.getBytes())));
    }


    /**
     * 生成公钥与私钥
     * @return 公钥与私钥对
     * @throws Exception 异常
     */
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(512);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    /**
     * 得到公钥，String 类型
     * @param keyPair 公钥与私钥对
     * @return 公钥的Base64编码
     */
    public static String getPublicKey(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        byte[] bytes = publicKey.getEncoded();
        return Base64Code.byte2base64(bytes);
    }

    /**
     * 得到私钥，String 类型
     * @param keyPair 公钥与私钥对
     * @return 私钥的Base64编码
     */
    public static String getPrivateKey(KeyPair keyPair) {
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] bytes = privateKey.getEncoded();
        return Base64Code.byte2base64(bytes);
    }

    /**
     * 将 String 类型的密钥转换为 PublicKey 对象
     * @param pubStr 公钥的Base64编码
     * @return 公钥
     * @throws Exception 异常
     */
    public static PublicKey string2PublicKey(String pubStr) throws Exception {
        byte[] keyBytes = Base64Code.base642byte(pubStr);
        /**
         * This class represents the ASN.1 encoding of a public key,
         * encoded according to the ASN.1 type
         */
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 将 String 类型的密钥转换为 PrivateKey 对象
     * @param priStr 私钥的Base64编码
     * @return 私钥
     * @throws Exception 异常
     */
    public static PrivateKey string2PrivateKey(String priStr) throws Exception {
        byte[] keyBytes = Base64Code.base642byte(priStr);
        /**
         * This class represents the ASN.1 encoding of a private key,
         * encoded according to the ASN.1 type
         */
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 利用 公钥 加密
     * @param content 待加密的数据
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception 异常
     */
    public static byte[] publicEncrypt(byte[] content, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(content);
        return bytes;
    }

    /**
     * 利用 私钥 解密
     * @param content 待解密的数据
     * @param privateKey 私钥
     * @return 明文
     * @throws Exception 异常
     */
    public static byte[] privateDecrypt(byte[] content, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = cipher.doFinal(content);
        return bytes;
    }

}
