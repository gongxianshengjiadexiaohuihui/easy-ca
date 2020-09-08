package com.ggp.noob.util;


import com.ggp.noob.asn1.AlgTypeEnum;
import com.ggp.noob.asn1.SignAlgEnum;
import com.ggp.noob.asn1.SignedAndEnvelopedData;
import com.ggp.noob.asn1.Sm2Cipher;
import com.ggp.noob.asn1.EncryptedContentInfo;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * @Author:ggp
 * @Date:2020-06-08 10:03
 * @Description:
 */
public class Asn1Util {

    /**
     * 生成数字信封 ---GMT0010
     *
     * @param signPublic    用户签名公钥
     * @param encPrivate    用户加密私钥
     * @param issuerSubject 签发者dn
     * @param issuerSn      签发者sn
     * @return
     */
    public static SignedAndEnvelopedData generateSignedAndEnvelopedData(Integer alg, PublicKey signPublic, PrivateKey encPrivate, String issuerSubject, String issuerSn) throws Exception {
        /**
         * 生成会话秘钥
         */
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128, new SecureRandom());
        SecretKey sessionKey = keyGenerator.generateKey();

        /**
         * 生成确认身份的信息
         */
        IssuerAndSerialNumber issuerAndSerialNumber = new IssuerAndSerialNumber(new X500Name(RFC4519Style.INSTANCE,issuerSubject), new BigInteger(issuerSn,16));
        /**
         * 语法版本号
         */
        ASN1Integer version = new ASN1Integer(1);
        /**
         * 组装接受者信息
         */
        KeyTransRecipientInfo recipientInfo = generateRecipientInfo(alg, signPublic, sessionKey, issuerAndSerialNumber);
        ASN1Set recipientInfos = new DERSet(recipientInfo);

        /**
         * HASH算法
         */
        AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(alg == AlgTypeEnum.RSA.alg ? X509ObjectIdentifiers.id_SHA1 : GMObjectIdentifiers.sm3);
        ASN1Set digestAlgorithms = new DERSet(digestAlgorithm);
        /**
         * 组装加密内容
         */
        EncryptedContentInfo encryptedContentInfo = generateEncryptedContentInfo(alg, encPrivate, sessionKey);
        /**
         * 组装签名内容
         */
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        os.write(version.getEncoded());
        os.write(recipientInfos.getEncoded());
        os.write(digestAlgorithms.getEncoded());
        os.write(encryptedContentInfo.getEncoded());

        /**
         * 组装签名者信息
         */
        SignerInfo signerInfo = generateSignerInfo(alg, encPrivate, issuerAndSerialNumber,os.toByteArray());
        ASN1Set signerInfos = new DERSet(signerInfo);
        return new SignedAndEnvelopedData(version,recipientInfos,digestAlgorithms,encryptedContentInfo,signerInfos);
    }

    /**
     * 生成签名者信息
     * @param alg                    算法
     * @param encPrivate             加密私钥
     * @param issuerAndSerialNumber  标识符
     * @param body
     * @return
     * @throws Exception
     */
    public static SignerInfo generateSignerInfo(Integer alg, PrivateKey encPrivate, IssuerAndSerialNumber issuerAndSerialNumber, byte[] body) throws Exception {
        SignerIdentifier signerIdentifier = new SignerIdentifier(issuerAndSerialNumber);
        AlgorithmIdentifier digestAlgorithm = null;
        AlgorithmIdentifier digestEncryptionAlgorithm = null;
        ASN1OctetString encryptedDigest = null;

        if (alg == AlgTypeEnum.RSA.alg) {
            digestAlgorithm = new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1);
            digestEncryptionAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
            encryptedDigest = new DEROctetString(SignatureUtil.sign(body, encPrivate, SignAlgEnum.SHA1_WITH_RSA));
        } else if (alg == AlgTypeEnum.SM2.alg) {
            digestAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm3);
            digestEncryptionAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign);
            encryptedDigest = new DEROctetString(SignatureUtil.sign(body, encPrivate, SignAlgEnum.SM3_WITH_SM2));
        }
        ASN1Set authenticatedAttributes = null;

        return new SignerInfo(signerIdentifier, digestAlgorithm, authenticatedAttributes, digestEncryptionAlgorithm, encryptedDigest, authenticatedAttributes);
    }

    /**
     * 生成加密内容
     *
     * @param alg
     * @param encPrivate
     * @param sessionKey
     * @return
     * @throws Exception
     */
    public static EncryptedContentInfo generateEncryptedContentInfo(Integer alg, PrivateKey encPrivate, SecretKey sessionKey) throws Exception {
        /**
         * 加密算法
         */
        AlgorithmIdentifier contentEncryptionAlgorithm = null;
        /**
         * 加密内容结果
         */
        ASN1OctetString encryptedContent = null;
        if (alg == AlgTypeEnum.RSA.alg) {
            /**
             * 卡暂时不支持AES
             */
            contentEncryptionAlgorithm = new AlgorithmIdentifier(Sm4Util.sm4);
            encryptedContent = new DEROctetString(Sm4Util.sm4_encrypt_ecb_pkcs5_padding(sessionKey.getEncoded(), PrivateKeyInfo.getInstance(encPrivate.getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded()));
        } else if (alg == AlgTypeEnum.SM2.alg) {
            contentEncryptionAlgorithm = new AlgorithmIdentifier(Sm4Util.sm4);
            BCECPrivateKey ecPrivateKey = (BCECPrivateKey) encPrivate;

            byte[] s = ecPrivateKey.getS().toByteArray();
            byte[] pri = new byte[32];
            if (s.length == 32) {
                System.arraycopy(s, 0, pri, 0, s.length);
            } else if (s.length < 32) {
                /**
                 * BigInteger会忽略末尾的0
                 */
                System.arraycopy(s, 0, pri, 0, s.length);
                for (int i = 0; i < 32 - s.length; i++) {
                    pri[s.length + i] = 0x00;
                }
            } else if (s.length > 32) {
                /**
                 * 密码机生成的私钥可能会填充了32个0，取后32字节，
                 */
                for (int i = 0; i < 32; i++) {
                    pri[31 - i] = s[s.length - i - 1];
                }
            }
            byte[] bytes = new byte[64];
            for (int i = 0; i <32 ; i++) {
                bytes[i]=0x00;
            }
            /**
             * 在原文前填充32个0
             */
            System.arraycopy(pri,0,bytes,32,32);
            encryptedContent = new DEROctetString(Sm4Util.sm4_encrypt_ecb_no_padding(sessionKey.getEncoded(),bytes));
        }
        return new EncryptedContentInfo(SignedAndEnvelopedData.OID, contentEncryptionAlgorithm, encryptedContent);
    }

    /**
     * @param alg                   算法
     * @param signPublic            签名公钥
     * @param sessionKey            会话秘钥
     * @param issuerAndSerialNumber 颁发者信息
     * @throws IOException
     * @throws InvalidCipherTextException
     */
    public static KeyTransRecipientInfo generateRecipientInfo(Integer alg, PublicKey signPublic, SecretKey sessionKey, IssuerAndSerialNumber issuerAndSerialNumber) throws IOException, InvalidCipherTextException {
        /**
         * 接受者标识符
         */
        RecipientIdentifier recipientIdentifier = new RecipientIdentifier(issuerAndSerialNumber);
        /**
         * 会话秘钥加密算法
         */
        AlgorithmIdentifier keyEncryptionAlgorithm = null;
        /**
         * 会话秘钥的加密结果
         */
        ASN1OctetString encryptedKey = null;
        AsymmetricKeyParameter keyParameter = PublicKeyFactory.createKey(SubjectPublicKeyInfo.getInstance(signPublic.getEncoded()));
        if (alg == AlgTypeEnum.RSA.alg) {
            /**
             * PKCS1格式的RSA公钥加密 c端都是pkcs1  bc封的pkcs8
             */
            keyEncryptionAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption);
            AsymmetricBlockCipher rsaEngine = new RSAEngine();
            rsaEngine.init(true, keyParameter);
            encryptedKey = new DEROctetString(rsaEngine.processBlock(sessionKey.getEncoded(), 0, sessionKey.getEncoded().length));
        } else if (alg == AlgTypeEnum.SM2.alg) {
            keyEncryptionAlgorithm = new AlgorithmIdentifier(GMObjectIdentifiers.sm2encrypt);
            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.init(true, new ParametersWithRandom(keyParameter,new SecureRandom()));
            byte[] cipherText = sm2Engine.processBlock(sessionKey.getEncoded(), 0, sessionKey.getEncoded().length);
            Sm2Cipher sm2Cipher = new Sm2Cipher((ECKeyParameters) keyParameter,cipherText,sessionKey.getEncoded().length);
            encryptedKey = new DEROctetString(sm2Cipher.getEncoded());
        }
        return new KeyTransRecipientInfo(recipientIdentifier, keyEncryptionAlgorithm, encryptedKey);
    }

}
