package com.ggp.noob;

import com.ggp.noob.asn1.SignedAndEnvelopedData;
import com.ggp.noob.pki.key.KeyUtil;
import com.ggp.noob.pki.p10.P10Util;
import com.ggp.noob.pki.pem.PemUtil;
import com.ggp.noob.util.Asn1Util;
import com.ggp.noob.util.CertUtil;
import com.ggp.noob.util.FileUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @Author:ggp
 * @Date:2020/8/11 15:00
 * @Description:
 */
public class CaService {
    static {
        if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 初始化，生成根证书
     */
    public void init(String alg) throws Exception {
        KeyPair keyPair;
        if (alg.equalsIgnoreCase("SM2")) {
            keyPair = KeyUtil.createSm2KeyPair();
        } else if (alg.equalsIgnoreCase("RSA")) {
            keyPair = KeyUtil.createRSAKeyPair(2048);
        } else {
            throw new IllegalArgumentException("不支持的算法类型alg:" + alg);
        }
        Date notBefore = new Date(System.currentTimeMillis());
        Date notAfter = new Date(System.currentTimeMillis() + Constant.validity);
        String signAlg = alg.equalsIgnoreCase("SM2") ? "SM3WITHSM2" : "SHA256WITHRSA";
        X509Certificate rootCert = CertUtil.generateCert("CN=root," + Constant.BASE_DN, "CN=root," + Constant.BASE_DN, BigInteger.valueOf(1L), notBefore, notAfter, keyPair.getPrivate(), keyPair.getPublic(), signAlg, null);
        CertUtil.writeObjectToFile(keyPair.getPrivate(), Constant.rootPri);
        CertUtil.writeObjectToFile(rootCert, Constant.rootCert);
        System.out.println("初始化完成，生成根证书成功");
    }
    public void issueCertWithNoP10(String savePath) throws Exception{
        X509Certificate rootCert = readRootCert();
        String signAlg;
        KeyPair keyPair;
        if (rootCert.getPublicKey() instanceof ECPublicKey) {
            signAlg = "SM3WITHSM2";
            keyPair = KeyUtil.createSm2KeyPair();
        } else {
            signAlg = "SHA256WITHRSA";
            keyPair = KeyUtil.createRSAKeyPair(2048);
        }
        long current = System.currentTimeMillis();
        String dn = "CN=" + current + ",O=XDJA,C=CN";
        X500Name subject = new X500Name(dn);
        PKCS10CertificationRequest p10 = P10Util.createP10(subject, signAlg, keyPair.getPublic(), keyPair.getPrivate());
        X509Certificate[] chain = this.issueCertWithP10(false, Base64.toBase64String(p10.getEncoded()), "single", savePath);
        PemUtil.writeObjectToFile(chain[0],savePath+"/user.cer");
        PemUtil.writeObjectToFile(rootCert,savePath+"/root.cer");
        PemUtil.writeObjectToFile(keyPair.getPrivate(),savePath+"/user.key");
        System.out.println("签发证书成功，证书位置" + savePath);
    }
    /**
     * 通过p10生成双证书
     *
     * @param p10PathOrStr
     * @throws Exception
     */
    public X509Certificate[] issueCertWithP10(boolean isPath, String p10PathOrStr, String type, String savePath) throws Exception {
        X509Certificate[] certs;
        String p10 = null;
        if (isPath) {
            p10 = FileUtil.readStringFromFile(p10PathOrStr);
        }else{
            p10=p10PathOrStr;
        }
        PublicKey signPub = CertUtil.getPublicKeyFromP10(p10);
        String subject = CertUtil.getSubjectFromP10(p10);
        KeyPair rootKeyPair = readRootKeyPair();
        String signAlg;
        KeyPair encKeyPair;
        if (rootKeyPair.getPublic() instanceof ECPublicKey) {
            signAlg = "SM3WITHSM2";
            encKeyPair = KeyUtil.createSm2KeyPair();
        } else {
            signAlg = "SHA256WITHRSA";
            encKeyPair = KeyUtil.createRSAKeyPair(2048);
        }
        long current = System.currentTimeMillis();
        Date notBefore = new Date(current);
        Date notAfter = new Date(current + Constant.validity);
        X509Certificate signCert = CertUtil.generateCert("CN=root," + Constant.BASE_DN, subject, BigInteger.valueOf(current), notBefore, notAfter, rootKeyPair.getPrivate(), signPub, signAlg, null);
        X509Certificate encCert = CertUtil.generateCert("CN=root," + Constant.BASE_DN, subject, BigInteger.valueOf(current), notBefore, notAfter, rootKeyPair.getPrivate(), encKeyPair.getPublic(), signAlg, null);
        String path = savePath + "/";
        if (type.equalsIgnoreCase("single")) {
            certs = new X509Certificate[2];
            certs[0] = signCert;
        } else if (type.equalsIgnoreCase("double")) {
            certs = new X509Certificate[3];
            certs[0] = signCert;
            certs[1] = encCert;
            this.complete(signCert, encCert, path, signPub, encKeyPair.getPrivate());
        } else {
            throw new IllegalArgumentException("type is only support [single|double]!");
        }
        System.out.println("签发证书成功，证书位置" + path);
        return certs;
    }

    public void issueP12WithNoP10(String savePath) throws Exception {
        X509Certificate rootCert = readRootCert();
        String signAlg;
        KeyPair keyPair;
        if (rootCert.getPublicKey() instanceof ECPublicKey) {
            signAlg = "SM3WITHSM2";
            keyPair = KeyUtil.createSm2KeyPair();
        } else {
            signAlg = "SHA256WITHRSA";
            keyPair = KeyUtil.createRSAKeyPair(2048);
        }
        long current = System.currentTimeMillis();
        String dn = "CN=" + current + ",O=XDJA,C=CN";
        X500Name subject = new X500Name(dn);
        PKCS10CertificationRequest p10 = P10Util.createP10(subject, signAlg, keyPair.getPublic(), keyPair.getPrivate());
        X509Certificate[] chain = this.issueCertWithP10(false, Base64.toBase64String(p10.getEncoded()), "single", savePath);
        String path = savePath + "/user.p12";
        KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
        keyStore.load(null, null);
        chain[1] = rootCert;
        char[] pwd = "111111".toCharArray();
        keyStore.setKeyEntry("user", keyPair.getPrivate(), pwd, chain);
        OutputStream os = new FileOutputStream(path);
        keyStore.store(os, pwd);
        os.close();
        System.out.println("文件保护密码6个1");
    }

    private KeyPair readRootKeyPair() throws Exception {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PEMKeyPair pemKeyPair = (PEMKeyPair) CertUtil.readPEM(new File(Constant.rootPri));
        return converter.getKeyPair(pemKeyPair);
    }

    private X509Certificate readRootCert() throws Exception {
        X509CertificateHolder holder = (X509CertificateHolder) CertUtil.readPEM(new File(Constant.rootCert));
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return converter.getCertificate(holder);
    }

    /**
     * 生成签名p7b，加密p7b，加密私钥数字信封0010
     *
     * @param signCert
     * @param encCert
     * @param path
     * @param privateKey
     */
    private void complete(X509Certificate signCert, X509Certificate encCert, String path, PublicKey publicKey, PrivateKey privateKey) throws Exception {
        X509Certificate rootCert = readRootCert();
        List<X509Certificate> list = new ArrayList<>();
        list.add(rootCert);
        list.add(signCert);
        FileUtil.writeStringToFile(path + "signCert.p7b", CertUtil.createCertChainByCerts(list));
        list.remove(signCert);
        list.add(encCert);
        FileUtil.writeStringToFile(path + "encCert.p7b", CertUtil.createCertChainByCerts(list));
        SignedAndEnvelopedData data = Asn1Util.generateSignedAndEnvelopedData(2, publicKey, privateKey, "CN=root," + Constant.BASE_DN, "1");
        FileUtil.writeBytesToFile(path + "signedAndEnvelopedData", data.getEncoded());
    }
}
