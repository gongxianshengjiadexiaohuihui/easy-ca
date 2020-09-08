package com.ggp.noob;

/**
 * @Author:ggp
 * @Date:2020/8/11 15:05
 * @Description:
 */
public class Constant {
    public static final String BASE_DN = "O=XDJA,C=CN";
    public static final String BASE_PATH = "/cert/";
    public static final String rootPri = BASE_PATH + "root/root.private";
    public static final String rootCert = BASE_PATH + "root/root.cer";
    public static final Long validity = 10 * 365 * 24 * 60 * 60 * 1000L;
}
