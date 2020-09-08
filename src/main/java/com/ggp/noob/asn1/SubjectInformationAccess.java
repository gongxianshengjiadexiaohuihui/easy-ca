package com.ggp.noob.asn1;


import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;

/**
 * @Author:ggp
 * @Date:2020-05-11 16:34
 * @Description:
 *    GM/T 0015-2012 P33
 *     https://devicepki.idmanagement.gov/certificateprofiles/ id-ad-caRepository (1.3.6.1.5.5.7.48.5):
 *     rfc3280
 *  *The SubjectInformationAccess object.
 *  * <pre>
 *  * id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
 *  *
 *  * SubjectInformationAccess  ::=
 *  *      SEQUENCE SIZE (1..MAX) OF AccessDescription
 *  * AccessDescription  ::=  SEQUENCE {
 *  *       accessMethod          OBJECT IDENTIFIER,
 *  *       accessLocation        GeneralName  }
 *  *
 *  * id-ad OBJECT IDENTIFIER ::= { id-pki 48 }
 *  * id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
 *  * id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
 *  * </pre>
 */

public class SubjectInformationAccess
        extends ASN1Object {

    /**
     * Page 47
     *    id-ad OBJECT IDENTIFIER ::= { id-pki 48 }
     *    id-ad-caRepository OBJECT IDENTIFIER ::= { id-ad 5 }
     *    id-ad-timeStamping OBJECT IDENTIFIER ::= { id-ad 3 }
     *
     *
     * Page 92
     *    -- access descriptor definitions
     * id-ad-ocsp         OBJECT IDENTIFIER ::= { id-ad 1 }
     * id-ad-caIssuers    OBJECT IDENTIFIER ::= { id-ad 2 }
     * id-ad-timeStamping OBJECT IDENTIFIER ::= { id-ad 3 }
     * id-ad-caRepository OBJECT IDENTIFIER ::= { id-ad 5 }
     */
    public final static ASN1ObjectIdentifier id_ad_caRepository = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.5");

    private AccessDescription[] descriptions;

    public static SubjectInformationAccess getInstance(
            Object obj) {
        if (obj instanceof SubjectInformationAccess) {
            return (SubjectInformationAccess) obj;
        }

        if (obj != null) {
            return new SubjectInformationAccess(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static SubjectInformationAccess fromExtensions(Extensions extensions) {
        return SubjectInformationAccess.getInstance(extensions.getExtensionParsedValue(Extension.subjectInfoAccess));
    }

    private SubjectInformationAccess(
            ASN1Sequence seq) {
        if (seq.size() < 1) {
            throw new IllegalArgumentException("sequence may not be empty");
        }

        descriptions = new AccessDescription[seq.size()];

        for (int i = 0; i != seq.size(); i++) {
            descriptions[i] = AccessDescription.getInstance(seq.getObjectAt(i));
        }
    }

    public SubjectInformationAccess(
            AccessDescription description) {
        this(new AccessDescription[]{description});
    }

    public SubjectInformationAccess(
            AccessDescription[] descriptions) {
        this.descriptions = new AccessDescription[descriptions.length];
        System.arraycopy(descriptions, 0, this.descriptions, 0, descriptions.length);
    }

    /**
     * create an SubjectInformationAccess with the oid and location provided.
     */
    public SubjectInformationAccess(
            ASN1ObjectIdentifier oid,
            GeneralName location) {
        this(new AccessDescription(oid, location));
    }

    /**
     * @return the access descriptions contained in this object.
     */
    public AccessDescription[] getAccessDescriptions() {
        return descriptions;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();

        for (int i = 0; i != descriptions.length; i++) {
            vec.add(descriptions[i]);
        }

        return new DERSequence(vec);
    }

    @Override
    public String toString() {
        return ("SubjectInformationAccess: Oid(" + this.descriptions[0].getAccessMethod().getId() + ")");
    }
}
