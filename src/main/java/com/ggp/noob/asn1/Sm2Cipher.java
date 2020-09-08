package com.ggp.noob.asn1;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.util.Enumeration;

/**
 * @Author:ggp
 * @Date:2020-06-08 19:39
 * @Description: SM2Cipher :: = SEQUENCE {
 * XCoordinate INTEGER,
 * YCoordinate INTEGER,
 * HASH OCTET STRING SIZE(32),
 * CipherText OCTET STRING
 * }
 */
public class Sm2Cipher extends ASN1Object {
    private ASN1Integer xCoordinate;
    private ASN1Integer yCoordinate;
    private ASN1OctetString hash;
    private ASN1OctetString cipherText;

    public static Sm2Cipher getInstance(Object o) {
        if (o instanceof Sm2Cipher) {
            return (Sm2Cipher) o;
        } else if (o != null) {
            return new Sm2Cipher(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public Sm2Cipher(ASN1Sequence sm2Asn1Sequence) {
        Enumeration e = sm2Asn1Sequence.getObjects();
        xCoordinate = ASN1Integer.getInstance(e.nextElement());
        yCoordinate = ASN1Integer.getInstance(e.nextElement());
        hash = ASN1OctetString.getInstance(e.nextElement());
        cipherText = ASN1OctetString.getInstance(e.nextElement());
    }

    public Sm2Cipher(ASN1Integer xCoordinate, ASN1Integer yCoordinate, ASN1OctetString hash, ASN1OctetString cipherText) {
        this.xCoordinate = xCoordinate;
        this.yCoordinate = yCoordinate;
        this.hash = hash;
        this.cipherText = cipherText;
    }

    /**
     *
     * @param keyParameters    密钥参数
     * @param cipherText       sm2加密结果
     * @param len              原文长度
     */
    public Sm2Cipher(ECKeyParameters keyParameters, byte[] cipherText,int len) {
        ECCurve curve = keyParameters.getParameters().getCurve();
        int curveLen = (curve.getFieldSize() + 7) / 8;
        byte[] c1 = new byte[curveLen * 2 + 1];
        System.arraycopy(cipherText, 0, c1, 0, c1.length);
        ECPoint point = curve.decodePoint(c1);
        this.xCoordinate = new ASN1Integer(BigIntegers.fromUnsignedByteArray(point.getXCoord().getEncoded()));
        this.yCoordinate = new ASN1Integer(BigIntegers.fromUnsignedByteArray(point.getYCoord().getEncoded()));

        byte[] hash = new byte[32];
        System.arraycopy(cipherText, cipherText.length - 32,hash,0,32 );
        this.hash = new DEROctetString(hash);

        byte[] text = new byte[len];
        System.arraycopy(cipherText,cipherText.length-32-len,text,0,len);
        this.cipherText = new DEROctetString(text);
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(xCoordinate);
        vector.add(yCoordinate);
        vector.add(hash);
        vector.add(cipherText);
        return new DERSequence(vector);
    }

}
