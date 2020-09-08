package com.ggp.noob.asn1;

import org.bouncycastle.asn1.*;

import java.util.Enumeration;

/**
 * @Author:ggp
 * @Date:2020-06-06 14:41
 * @Description: SignedAndEnvelopedData :: = SEQUENCE {
 * version(1) Version
 * recipientInfos RecipientInfos
 * digestAlgorithms DigestAlgorithmIdentifiers
 * encryptedContentInfo EncryptedContentInfo
 * certificates[0] IMPLICIT ExtendedCertificatesAndCertificates OPTIONAL
 * crls[1] IMPLICIT CertificatesRevocationLists OPTIONAL
 * signerInfos SignerInfos
 * }
 */
public class SignedAndEnvelopedData extends ASN1Object {
    /**
     * GMT-0010
     */
    public static ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.2.156.10197.6.1.4.2.104");
    /**
     * 语法版本号
     */
    private ASN1Integer version;
    /***
     * 每个接受者信息的集合，至少一个元素
     */
    private ASN1Set recipientInfos;
    /**
     * 消息摘要算法标识符的集合
     */
    private ASN1Set digestAlgorithms;
    /**
     * 已经加密的内容
     */
    private EncryptedContentInfo encryptedContentInfo;
    /**
     * 证书集合  可选
     */
    private ASN1Set certificates;
    /**
     * crl集合  可选
     */
    private ASN1Set crls;
    /**
     * 签名者信息集合，至少要有一个元素
     */
    private ASN1Set signerInfos;

    public SignedAndEnvelopedData() {
    }


    public SignedAndEnvelopedData(ASN1Integer version,ASN1Set recipientInfos, ASN1Set digestAlgorithms, EncryptedContentInfo encryptedContentInfo, ASN1Set signerInfos) {
        this.version = version;
        this.recipientInfos = recipientInfos;
        this.digestAlgorithms = digestAlgorithms;
        this.encryptedContentInfo = encryptedContentInfo;
        this.signerInfos = signerInfos;
    }

    public static SignedAndEnvelopedData getInstance(Object obj) {
        if (obj instanceof SignedAndEnvelopedData) {
            return (SignedAndEnvelopedData) obj;
        } else if (obj instanceof ASN1Sequence) {
            return new SignedAndEnvelopedData((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Unknown type "+obj.getClass().getName());
    }

    public SignedAndEnvelopedData(ASN1Sequence sequence) {
        Enumeration e = sequence.getObjects();
        this.version = (ASN1Integer) e.nextElement();
        if (version.getValue().intValue() != 1) {
            throw new IllegalArgumentException("SignedAndEnvelopedData not version 1");
        }
        this.recipientInfos = (ASN1Set) e.nextElement();
        this.digestAlgorithms = (ASN1Set) e.nextElement();
        this.encryptedContentInfo = EncryptedContentInfo.getInstance(e.nextElement());
        while (e.hasMoreElements()) {
            ASN1Object o = (ASN1Object) e.nextElement();
            if (o instanceof DERTaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) o;
                switch (tagged.getTagNo()) {
                    case 0:
                        this.certificates = ASN1Set.getInstance(tagged, false);
                        break;
                    case 1:
                        this.crls = ASN1Set.getInstance(tagged, false);
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown tag value" + tagged);
                }
            } else {
                this.signerInfos = (ASN1Set) o;
            }
        }

    }

    /**
     * Method providing a primitive representation of this object suitable for encoding.
     *
     * @return a primitive representation of this object.
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(this.version);
        vector.add(this.recipientInfos);
        vector.add(this.digestAlgorithms);
        vector.add(this.encryptedContentInfo);

        if(null != this.certificates){
            vector.add(new DERTaggedObject(false,0,this.certificates));
        }
        if(null != this.crls){
            vector.add(new DERTaggedObject(false,1,this.crls));
        }
        vector.add(this.signerInfos);

        return new DERSequence(vector);
    }

    public ASN1Integer getVersion() {
        return version;
    }

    public void setVersion(ASN1Integer version) {
        this.version = version;
    }

    public ASN1Set getRecipientInfos() {
        return recipientInfos;
    }

    public void setRecipientInfos(ASN1Set recipientInfos) {
        this.recipientInfos = recipientInfos;
    }

    public ASN1Set getDigestAlgorithms() {
        return digestAlgorithms;
    }

    public void setDigestAlgorithms(ASN1Set digestAlgorithms) {
        this.digestAlgorithms = digestAlgorithms;
    }

    public EncryptedContentInfo getEncryptedContentInfo() {
        return encryptedContentInfo;
    }

    public void setEncryptedContentInfo(EncryptedContentInfo encryptedContentInfo) {
        this.encryptedContentInfo = encryptedContentInfo;
    }

    public ASN1Set getCertificates() {
        return certificates;
    }

    public void setCertificates(ASN1Set certificates) {
        this.certificates = certificates;
    }

    public ASN1Set getCrls() {
        return crls;
    }

    public void setCrls(ASN1Set crls) {
        this.crls = crls;
    }

    public ASN1Set getSignerInfos() {
        return signerInfos;
    }

    public void setSignerInfos(ASN1Set signerInfos) {
        this.signerInfos = signerInfos;
    }
}
