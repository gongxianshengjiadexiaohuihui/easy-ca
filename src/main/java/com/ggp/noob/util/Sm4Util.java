package com.ggp.noob.util;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * @Author:ggp
 * @Date:2020-06-08 14:42
 * @Description:
 */
public class Sm4Util {
    public static final ASN1ObjectIdentifier sm4 = GMObjectIdentifiers.sm_scheme.branch("104");

    /**
     * sm4_ecb加密，填充方式pkcs5padding
     * @param key      秘钥
     * @param data     原文
     * @return
     */
    public static byte[] sm4_encrypt_ecb_pkcs5_padding(byte[] key,byte[] data) throws Exception {
        javax.crypto.Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
        Key keySpec = new SecretKeySpec(key,"SM4");
        cipher.init(1,keySpec);
        return cipher.doFinal(data);
    }
    /**
     * sm4_ecb加密，填充方式noPadding
     * @param key      秘钥
     * @param data     原文
     * @return
     */
    public static byte[] sm4_encrypt_ecb_no_padding(byte[] key,byte[] data) throws Exception {
        javax.crypto.Cipher cipher = Cipher.getInstance("SM4/ECB/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
        Key keySpec = new SecretKeySpec(key,"SM4");
        cipher.init(1,keySpec);
        return cipher.doFinal(data);
    }
    /**
     * sm4_ecb加密，填充方式Pkcs7
     * @param key      秘钥
     * @param data     原文
     * @return
     */
    public static byte[] sm4_encrypt_ecb_pkcs7_padding(byte[] key,byte[] data) throws Exception {
        javax.crypto.Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", BouncyCastleProvider.PROVIDER_NAME);
        Key keySpec = new SecretKeySpec(key,"SM4");
        cipher.init(1,keySpec);
        return cipher.doFinal(data);
    }
}
