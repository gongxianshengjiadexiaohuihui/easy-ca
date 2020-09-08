package com.ggp.noob.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;

/**
 * @Author:ggp
 * @Date:2020-06-06 17:57
 * @Description:
 * EncryptedContentInfo :: = SEQUENCE {
 *     contentType ContentType
 *     contentEncryptionAlgorithm ContentEncryptionAlgorithm
 *     encryptedContent[0] IMPLICIT EncryptedContent OPTIONAL
 *     sharedInfo[1] IMPLICIT OCTET STRING OPTIONAL
 *     sharedInfo[2] IMPLICIT OCTET STRING OPTIONAL
 * }
 */
public class EncryptedContentInfo extends ASN1Object {
    /**
     * 内容类型
     */
    private ASN1ObjectIdentifier contentType;
    /**
     * 内容加密算法
     */
    private AlgorithmIdentifier contentEncryptionAlgorithm;
    /**
     * 已经加密的内容  可选
     */
    private ASN1OctetString encryptedContent;
    /**
     * 协商好的共享信息 可选
     */
    private ASN1OctetString sharedInfo1;
    /**
     * 协商好的共享信息 可选
     */
    private ASN1OctetString sharedInfo2;

    public EncryptedContentInfo(ASN1ObjectIdentifier contentType, AlgorithmIdentifier contentEncryptionAlgorithm, ASN1OctetString encryptedContent) {
        this.contentType = contentType;
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        this.encryptedContent = encryptedContent;
    }

    public EncryptedContentInfo(ASN1Sequence sequence){
        Enumeration e = sequence.getObjects();
        this.contentType = (ASN1ObjectIdentifier)e.nextElement();
        this.contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());
        while (e.hasMoreElements()){
            ASN1TaggedObject tagged = (ASN1TaggedObject)e.nextElement();
            switch (tagged.getTagNo()){
                case 0:
                    this.encryptedContent = ASN1OctetString.getInstance(tagged,false);
                    break;
                case 1:
                    this.sharedInfo1 = ASN1OctetString.getInstance(tagged,false);
                    break;
                case 2:
                    this.sharedInfo2 = ASN1OctetString.getInstance(tagged,false);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown tag value" + tagged);
            }
        }

    }

    public static EncryptedContentInfo getInstance(Object obj){
        if(obj instanceof EncryptedContentInfo){
            return (EncryptedContentInfo)obj;
        }else if(obj instanceof ASN1Sequence){
            return new EncryptedContentInfo((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("Unknown type "+obj.getClass().getName());
    }
    /**
     * Method providing a primitive representation of this object suitable for encoding.
     *
     * @return a primitive representation of this object.
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(this.contentType);
        vector.add(this.contentEncryptionAlgorithm);
        if(null != this.encryptedContent){
            vector.add(new DERTaggedObject(false,0,this.encryptedContent));
        }
        if(null != this.sharedInfo1){
            vector.add(new DERTaggedObject(false,0,this.sharedInfo1));
        }
        if(null != this.sharedInfo2){
            vector.add(new DERTaggedObject(false,0,this.sharedInfo2));
        }
        return new DERSequence(vector);
    }

    public ASN1ObjectIdentifier getContentType() {
        return contentType;
    }

    public void setContentType(ASN1ObjectIdentifier contentType) {
        this.contentType = contentType;
    }

    public AlgorithmIdentifier getContentEncryptionAlgorithm() {
        return contentEncryptionAlgorithm;
    }

    public void setContentEncryptionAlgorithm(AlgorithmIdentifier contentEncryptionAlgorithm) {
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
    }

    public ASN1OctetString getEncryptedContent() {
        return encryptedContent;
    }

    public void setEncryptedContent(ASN1OctetString encryptedContent) {
        this.encryptedContent = encryptedContent;
    }

    public ASN1OctetString getSharedInfo1() {
        return sharedInfo1;
    }

    public void setSharedInfo1(ASN1OctetString sharedInfo1) {
        this.sharedInfo1 = sharedInfo1;
    }

    public ASN1OctetString getSharedInfo2() {
        return sharedInfo2;
    }

    public void setSharedInfo2(ASN1OctetString sharedInfo2) {
        this.sharedInfo2 = sharedInfo2;
    }
}
