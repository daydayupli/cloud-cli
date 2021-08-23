/*
package com.platform.common.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.security.AlgorithmParameters;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

*/
/**
 * Description: Aes加密
 *//*

public class AesUtil {
    public static final String AES_ENCRYPT_PASSWORD = "1f17417b2227b356";
    public static final String AES_ENCRYPT_VI = "ab6b2dfd69f5fb91";

    */
/**
     * aes加密
     * @param content
     * @param password
     * @param vi
     * @return
     *//*

    public static String aesPKCS7PaddingEncrypt(String content, String password, String vi) {

        try {
            initialize();

            KeyGenerator kgen = KeyGenerator.getInstance("AES");// 创建AES的Key生产者

            // kgen.init(128, new SecureRandom(password.getBytes()));// 利用用户密码作为随机数初始化出

            // 128位的key生产者
            // 加密没关系，SecureRandom是生成安全随机数序列，password.getBytes()是种子，只要种子相同，序列就一样，所以解密只要有password就行

            SecretKey secretKey = kgen.generateKey();// 根据用户密码，生成一个密钥

            byte[] enCodeFormat = secretKey.getEncoded();// 返回基本编码格式的密钥，如果此密钥不支持编码，则返回
            // null。
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");// 创建密码器

            byte[] byteContent = content.getBytes("utf-8");
            AlgorithmParameterSpec paramSpec = new IvParameterSpec(vi.getBytes());
            SecretKeySpec key = new SecretKeySpec(password.getBytes(), "AES");// 转换为AES专用密钥

            cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);// 初始化为加密模式的密码器

            byte[] result = cipher.doFinal(byteContent);// 加密

            return Hex.encodeHexString(result);// 通过Base64转码返回
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    */
/**
     * aes解密
     * @param content
     * @param password
     * @param vi
     * @return
     *//*

    public static String aesPKCS7PaddingDecrypt(String content, String password, String vi) {

        try {
            initialize();

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");// 创建密码器
            byte[] byteContent = Hex.decodeHex(content);

            AlgorithmParameters params = AlgorithmParameters.getInstance("AES");
            params.init(new IvParameterSpec(vi.getBytes()));
            SecretKeySpec key = new SecretKeySpec(password.getBytes(), "AES");// 转换为AES专用密钥


            cipher.init(Cipher.DECRYPT_MODE, key, params);// 初始化为加密模式的密码器

            byte[] result = cipher.doFinal(byteContent);// 加密

            return new String(result);// 通过Base64转码返回
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    private static boolean initialized = false;

    public static void initialize() {
        if (initialized) {
            return;
        }
        Security.addProvider(new BouncyCastleProvider());
        initialized = true;
    }
}
*/
