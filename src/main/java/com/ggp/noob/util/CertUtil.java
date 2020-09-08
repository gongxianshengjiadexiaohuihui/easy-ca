package com.ggp.noob.util;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * @Author:ggp
 * @Date:2020/8/11 14:58
 * @Description:
 */
public class CertUtil {

    /**
     * 生成证书
     * @param issuer     颁发者dn
     * @param subject    使用者证书主体
     * @param sn         使用者证书sn
     * @param notBefore  生效时间
     * @param notAfter   失效时间
     * @param issuerKey  颁发者私钥
     * @param publicKey  使用者公钥
     * @param signAlg    签名算法
     * @param extensions 证书扩展项
     * @return
     */
    public static X509Certificate generateCert(String issuer, String subject, BigInteger sn, Date notBefore, Date notAfter, PrivateKey issuerKey, PublicKey publicKey, String signAlg, List<Extension> extensions) throws Exception{
        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(signAlg);
        ContentSigner contentSigner = contentSignerBuilder.build(issuerKey);
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(new X500Name(RFC4519Style.INSTANCE,issuer),sn,notBefore,notAfter,new X500Name(RFC4519Style.INSTANCE,subject),subjectPublicKeyInfo);
        if(null != extensions){
            Iterator<Extension> iterator = extensions.iterator();
            while (iterator.hasNext()){
                Extension extension = iterator.next();
                builder.addExtension(extension);
            }
        }
        X509CertificateHolder holder = builder.build(contentSigner);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
        return converter.getCertificate(holder);
    }
    /**
     * 将对象写入文件
     *
     * @param object 见pemUtil-@Description
     * @param path   写入路径
     */
    public static void writeObjectToFile(Object object, String path) {
        CharArrayWriter writer = new CharArrayWriter();
        PEMWriter pemWriter = new PEMWriter(writer);
        File file = new File(path);
        file.getParentFile().mkdirs();
        FileOutputStream fileOutputStream = null;
        try {
            pemWriter.writeObject(object);
            pemWriter.close();
            fileOutputStream = new FileOutputStream(file);
            fileOutputStream.write(writer.toString().getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("写入文件失败", e);
        }
    }
    /**
     * 解析PEM文件
     *
     * @param file
     * @return
     */
    public static Object readPEM(File file) throws Exception {
        PEMParser parser = new PEMParser(new FileReader(file));
        Object obj = parser.readObject();
        parser.close();
        return obj;
    }
    /**
     * 打印pemObject
     * @param pemObject
     * @return
     * @throws Exception
     */
    public static String writePemObject(PemObject pemObject) throws Exception {
        PemWriter pemWriter = null;
        try {
            StringWriter stringWriter = new StringWriter();
            pemWriter = new PemWriter(stringWriter);
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
            return stringWriter.toString();
        } catch (Exception e) {
            throw new Exception("打印pemObject对象异常",e);
        } finally {
            if (null != pemWriter) {
                pemWriter.close();
            }
        }
    }
    /**
     * 进行p7b的pem格式转换
     * @param contentInfo
     * @author ssh
     * @return
     * @throws Exception
     */
    public static String writeP7bPem(ContentInfo contentInfo) throws Exception {
        try {
            PemObject pemObject = new PemObject("PKCS7",contentInfo.getEncoded(ASN1Encoding.DER));
            return CertUtil.writePemObject(pemObject);
        } catch (Exception e) {
            throw new Exception("将p7b对象转换为Pem格式异常",e);
        }
    }

    /**
     * 生成符合PKCS7 singedData格式的pem证书链
     * @param certificateList
     * @author ssh
     * @return
     * @throws Exception
     */
    public static String createCertChainByCerts(List<X509Certificate> certificateList) throws Exception {

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        try {
            CMSProcessableByteArray msg = new CMSProcessableByteArray("".getBytes());
            JcaCertStore jcaCertStore = new JcaCertStore(certificateList);
            gen.addCertificates(jcaCertStore);
            CMSSignedData cmsSignedData = gen.generate(msg);
            return CertUtil.writeP7bPem(cmsSignedData.toASN1Structure());
        } catch (Exception e) {
            throw new Exception("创建证书链异常",e);
        }
    }

    public static final String P10_HEAD = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String P10_TAIL = "-----END CERTIFICATE REQUEST-----";
    /**
     * 从p10中解析publickey
     *
     * @param p10
     * @return
     * @auth ssh
     */
    public static PublicKey getPublicKeyFromP10(String p10) throws Exception {
        p10 = p10.replace(P10_TAIL, "").replace(P10_HEAD, "");
        p10 = p10.replace("\r", "").replace("\n", "");
        p10 = p10.replace("\\r", "").replace("\\n", "");
        PKCS10CertificationRequest re = new PKCS10CertificationRequest(Base64.decode(p10));
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        PublicKey publicKey = converter.getPublicKey(re.getSubjectPublicKeyInfo());
        return publicKey;
    }

    /**
     * 从p10中解析证书主体
     *
     * @param p10
     * @return
     * @auth ssh
     */
    public static String getSubjectFromP10(String p10) throws Exception{
        p10 = p10.replace(P10_TAIL, "").replace(P10_HEAD, "");
        p10 = p10.replace("\r", "").replace("\n", "");
        p10 = p10.replace("\\r", "").replace("\\n", "");
        PKCS10CertificationRequest re = new PKCS10CertificationRequest(Base64.decode(p10));
        return re.getSubject().toString();
    }
}
