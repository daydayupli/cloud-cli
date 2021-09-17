package com.platform.common.utils;

import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import java.security.*;
import java.util.Map;

/**
 * Description: 数字签名
 *
 * @author lihaibo
 * @version 1.0.0, 2021/9/17
 * @since JDK 1.8
 */
public class SignatureUtil {
    public static void main(String[] args) {
        String a = "123";

        String algorithm = "RSA";
        Map<String, String> map = RsaUtil.generateKey(algorithm);
        PublicKey publicKey = RsaUtil.getPublicKey(map.get("publicKey"), algorithm);
        PrivateKey privateKey = RsaUtil.getPrivateKey(map.get("privateKey"), algorithm);

        // 获取数字签名
        String signaturedData = getSignature(a, "sha256withrsa",
                privateKey);
        System.out.println("数字签名:" + signaturedData);
        // 校验签名
        boolean b = verifySignature(a, "sha256withrsa", publicKey,
                signaturedData);
        System.out.println("校验：" + b);
    }

    /**
     * 校验签名
     * @param input 表示原文
     * @param algorithm 表示算法
     * @param publicKey 公钥key
     * @param signaturedData 签名密文
     * @return
     */
    public static boolean verifySignature(String input, String algorithm, PublicKey publicKey, String signaturedData) {
        try {
            // 获取签名对象
            Signature signature = Signature.getInstance(algorithm);
            // 初始化校验
            signature.initVerify(publicKey);
            // 传入原文
            signature.update(input.getBytes());
            // 校验数据
            return signature.verify(Base64.decode(signaturedData));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (Base64DecodingException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 生成数字签名
     * @param input 表示原文
     * @param algorithm  表示算法
     * @param privateKey 私钥key
     * @return
     */
    public static String getSignature(String input, String algorithm, PrivateKey privateKey){
        try {
            // 获取签名对象
            Signature signature = Signature.getInstance(algorithm);
            // 初始化签名
            signature.initSign(privateKey);
            // 传入原文
            signature.update(input.getBytes());
            // 开始签名
            byte[] sign = signature.sign();
            // 使用base64进行编码
            return Base64.encode(sign);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }
}
