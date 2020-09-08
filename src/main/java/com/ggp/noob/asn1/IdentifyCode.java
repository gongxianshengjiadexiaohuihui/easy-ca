package com.ggp.noob.asn1;

import org.bouncycastle.asn1.*;

/**
 * 证书扩展项-个人身份标识码 identifyCode 结构封装，参考GMT 0015-2012基于SM2密码算法的数字证书格式.pdf
 *  <pre>
 *     IdentifyCode  ::= CHOICE {
 *       residenterCardNumber          [0] PrintableString,
 *       militaryOfficerCardNumber     [1] UTF8String,
 *       passportNumber                [2] PrintableString
 *     }
 * </pre>
 * 说明：residenterCardNumber      - 身份证号码
 *     militaryOfficerCardNumber - 军官证号码
 *     passportNumber            - 护照号码
 * <p>
* @Description: 
* @author zjr
* @date 2019年5月15日
 */
public class IdentifyCode extends ASN1Object implements ASN1Choice{

	 public static final int  residenterCardNumberTag = 0;
	 public static final int  militaryOfficerCardNumberTag = 1;
	 public static final int  passportNumberTag = 2;
	
	 private DERPrintableString residenterCardNumber;
	 private DERUTF8String militaryOfficerCardNumber;
	 private DERPrintableString passportNumber;

	 public IdentifyCode(DERPrintableString residenterCardNumber, DERUTF8String militaryOfficerCardNumber, DERPrintableString passportNumber) {
		this.residenterCardNumber = residenterCardNumber;
		this.militaryOfficerCardNumber = militaryOfficerCardNumber;
		this.passportNumber = passportNumber;
	 }
	

	public static IdentifyCode getInstance(Object obj) {
		if (obj == null || obj instanceof IdentifyCode) {
			return (IdentifyCode) obj;
		} else if (obj instanceof ASN1TaggedObject) {
			return new IdentifyCode((ASN1TaggedObject) obj);
		}

		throw new IllegalArgumentException("unknown object in factory: " + obj.getClass());
	}
	
	private IdentifyCode(ASN1TaggedObject tagObj) {
		switch (tagObj.getTagNo()) {
		case residenterCardNumberTag:
			residenterCardNumber = DERPrintableString.getInstance(tagObj, true);
			break;
		case militaryOfficerCardNumberTag:
			militaryOfficerCardNumber = DERUTF8String.getInstance(tagObj,true);
			break;
		case passportNumberTag:
			passportNumber = DERPrintableString.getInstance(tagObj, true);
			break;
		default:
			throw new IllegalArgumentException("unknown tag: " + tagObj.getTagNo());
		}
	}
	/**
	 * 获取身份标识类型
	 * @return
	 */
	public int getType(){
        if (residenterCardNumber != null)
        {
            return residenterCardNumberTag;
        }
        if (militaryOfficerCardNumber != null)
        {
            return militaryOfficerCardNumberTag;
        }
        return passportNumberTag;
    }
    /**
     *  获取个人身份标识码
     * @return
     */
	public ASN1String getIdentifyCode() {
		if (residenterCardNumber != null)
        {
            return residenterCardNumber;
        }
        if (militaryOfficerCardNumber != null)
        {
            return militaryOfficerCardNumber;
        }
        return passportNumber;
	}

	  
	@Override
	public ASN1Primitive toASN1Primitive() {
		if (residenterCardNumber != null) {
			return new DERTaggedObject(true, 0, residenterCardNumber);
		} else if (militaryOfficerCardNumber != null) {
			return new DERTaggedObject(true, 1, militaryOfficerCardNumber);
		}
		return new DERTaggedObject(true, 2, passportNumber);
	}
}
