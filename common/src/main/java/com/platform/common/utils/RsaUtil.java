package com.platform.common.utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Description: RSA加解密
 *
 * @author lihaibo
 * @version 1.0.0, 2021/8/23
 * @since JDK 1.8
 */
public class RsaUtil {

    /**
     * 解密数据
     *
     * @param algorithm      : 算法
     * @param encrypted      : 密文
     * @param publicKeyString            : 密钥
     * @return : 原文
     * @throws Exception
     */
    public static String decryptRSA(String algorithm, String publicKeyString, String encrypted) {
        try {
            // 创建key的工厂
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            // 创建公钥规则
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            // 创建加密对象
            Cipher cipher = Cipher.getInstance(algorithm);
            // 私钥解密
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            // 使用base64进行转码
            byte[] decode = Base64.getDecoder().decode(encrypted);

            // 使用私钥进行解密
            byte[] bytes1 = cipher.doFinal(decode);
            return new String(bytes1);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 使用密钥加密数据
     *
     * @param algorithm      : 算法
     * @param input          : 原文
     * @param privateKeyString            : 密钥
     * @return : 密文
     * @throws Exception
     */
    public static String encryptRSA(String algorithm, String privateKeyString, String input) {
        try {
            // 创建key的工厂
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            // 创建私钥key的规则
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyString));
            // 返回私钥对象
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            // 创建加密对象
            Cipher cipher = Cipher.getInstance(algorithm);
            // 对加密进行初始化
            // 第一个参数：加密的模式
            // 第二个参数：你想使用公钥加密还是私钥加密
            // 我想使用私钥进行加密
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);

            // 使用私钥进行加密
            byte[] bytes = cipher.doFinal(input.getBytes());
            return Base64.getEncoder().encodeToString(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 生产公钥和私钥
     * @param algorithm 算法
     */
    public static Map<String, String> generateKey(String algorithm) {
        try {
            // 密钥对生成器对象
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            // 生成密钥对
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            // 生成私钥
            PrivateKey privateKey = keyPair.getPrivate();
            // 生成公钥
            PublicKey publicKey = keyPair.getPublic();
            // 获取私钥的字节数组
            byte[] privateKeyEncoded = privateKey.getEncoded();
            // 获取公钥字节数组
            byte[] publicKeyEncoded = publicKey.getEncoded();
            // 使用base64进行编码
            String privateEncodeString = Base64.getEncoder().encodeToString(privateKeyEncoded);
            String publicEncodeString = Base64.getEncoder().encodeToString(publicKeyEncoded);
            System.out.println("私钥：" + privateEncodeString);
            System.out.println("公钥：" + publicEncodeString);
            Map<String, String> map = new HashMap<>(2);
            map.put("privateKey", privateEncodeString);
            map.put("publicKey", publicEncodeString);
            return map;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return Collections.emptyMap();
    }

    /**
     * 读取公钥
     * @param publicKeyString 公钥串
     * @param algorithm  算法
     * @return
     */
    public static PublicKey getPublicKey(String publicKeyString, String algorithm) {
        try {
            // 创建key的工厂
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            // 创建公钥规则
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
                    Base64.getDecoder().decode(publicKeyString));
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     *  读取私钥
     * @param privateKeyString 私钥串
     * @param algorithm 算法
     * @return 返回私钥的key对象
     */
    public static PrivateKey getPrivateKey(String privateKeyString, String algorithm) {
        try {
            // 创建key的工厂
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            // 创建私钥key的规则
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(privateKeyString));
            // 返回私钥对象
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        String input = "测试test123";
        // 创建密钥对
        String algorithm = "RSA";
        Map<String, String> map = generateKey(algorithm);

        //  私钥加密
        String encrypt = encryptRSA(algorithm, map.get("privateKey"), input);
        System.out.println("加密：" + encrypt);

        // 公钥解密
        String decrypt = decryptRSA(algorithm, map.get("publicKey"), encrypt);
        System.out.println("解密：" + decrypt);

    }
}
