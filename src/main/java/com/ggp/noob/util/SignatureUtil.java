package com.ggp.noob.util;

import com.ggp.noob.asn1.SignAlgEnum;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * @Author:ggp
 * @Date:2020-06-08 15:59
 * @Description:
 */
public class SignatureUtil {
    /**
     * 签名
     * @param plain      原文
     * @param key        私钥
     * @param algEnum    签名算法
     * @return
     * @throws Exception
     */
    public static byte[] sign(byte[] plain, PrivateKey key, SignAlgEnum algEnum) throws Exception {
        Signature signature = Signature.getInstance(algEnum.value, BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(key);
        signature.update(plain);
        return signature.sign();
    }

    /**
     * 验签
     * @param plain      原文
     * @param cipher     密文
     * @param key        公钥
     * @param algEnum    签名算法
     * @return
     * @throws Exception
     */
    public static boolean verify(byte[] plain, byte[] cipher, PublicKey key, SignAlgEnum algEnum) throws Exception {
        Signature signature = Signature.getInstance(algEnum.value,BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(key);
        signature.update(plain);
        return signature.verify(cipher);
    }
}
