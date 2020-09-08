package com.ggp.noob.asn1;

/**
 * @Author:ggp
 * @Date:2020-06-08 11:11
 * @Description:
 */
public enum AlgTypeEnum {
    RSA(1),
    SM2(2)
    ;
    public int alg;

    AlgTypeEnum(int alg) {
        this.alg = alg;
    }
}
