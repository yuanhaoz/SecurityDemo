package com.zyh.对称加密算法;

import com.zyh.数字摘要.Base64Code;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 基于 Java 的 DES 算法的使用。
 * @author yuanhao
 * @date 2018/6/16 16:25
 */
public class DesDemo {

    public static void main(String[] args) throws Exception {
//        System.out.println(genKeyDES());
//        System.out.println(genKeyDES().length());

        String str = "hello, i am world, good night!";
        String keyBase64 = genKeyDES(); // Base64算法编码后输出 DES密钥
        System.out.println(keyBase64);
        SecretKey key = loadKeyDES(keyBase64); // DES 密钥
        byte[] bytes = encryptDES(str.getBytes(), key); // 生成 DES 密文
        System.out.println(Base64Code.byte2base64(bytes)); // Base64算法编码后输出密文
        byte[] souceBytes = decryptDES(bytes, key); // 解密
    }

    /**
     * 生成 DES 密钥
     * @return 密钥的Base64编码
     * @throws Exception 异常
     */
    public static String genKeyDES() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        keyGenerator.init(56);
        SecretKey key = keyGenerator.generateKey();
        String base64Str = Base64Code.byte2base64(key.getEncoded());
        return base64Str;
    }

    /**
     * 从Base64编码加载 DES 密钥
     * @param base64Key 密钥的Base64编码
     * @return 密钥
     * @throws Exception 异常
     */
    public static SecretKey loadKeyDES(String base64Key) throws Exception {
        byte[] bytes = Base64Code.base642byte(base64Key);
        SecretKey key = new SecretKeySpec(bytes, "DES");
        return key;
    }

    /**
     * 利用DES密钥 加密
     * @param source 待加密的数据
     * @param key DES密钥
     * @return 密文
     * @throws Exception 异常
     */
    public static byte[] encryptDES(byte[] source, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipher.doFinal(source);
        return bytes;
    }

    /**
     * 利用DES密钥 解密
     * @param source 待解密的数据
     * @param key DES密钥
     * @return 明文
     * @throws Exception 异常
     */
    public static byte[] decryptDES(byte[] source, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] bytes = cipher.doFinal(source);
        return bytes;
    }

}
