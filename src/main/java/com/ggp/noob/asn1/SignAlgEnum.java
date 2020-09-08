package com.ggp.noob.asn1;

/**
 * @Author:ggp
 * @Date:2020-05-13 16:23
 * @Description:
 */
public enum SignAlgEnum {
    SHA256_WITH_RSA("1","SHA256WITHRSA"),
    SM3_WITH_SM2("2","SM3WITHSM2"),
    SHA1_WITH_RSA("3","SHA1WITHRSA")
    ;
    public String code;
    public String value;

    SignAlgEnum(String code, String value) {
        this.code = code;
        this.value = value;
    }
    public static String getCode(String value){
        for(SignAlgEnum signAlgEnum:SignAlgEnum.values()){
            if(value.equalsIgnoreCase(signAlgEnum.value)){
                return signAlgEnum.code;
            }
        }
        throw new RuntimeException("不支持的签名算法"+value);
    }
}
