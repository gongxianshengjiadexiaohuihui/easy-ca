package com.ggp.noob;

/**
 * @Author:ggp
 * @Date:2020/8/11 14:57
 * @Description:
 */
public class Main {
    static  StringBuilder help = new StringBuilder("命令参数\n")
            .append("-init               alg                          初始化根证书，alg可以传RSA,或SM2\n")
            .append("-issueCertWithP10   path  type   savePath        签发证书，会返回文件路径,path为p10路径，type为single表示单证,type为double表示双证,savePath为指定文件路径\n")
            .append("-issueCertWithNoP10 savePath                     签发单证书，会返回文件路径，savePath为指定文件路径\n")
            .append("-issueP12WithNoP10  savePath                     无p10签发p12，会返回文件路径,savePath为指定文件路径\n");
    public static void main(String[] args) throws Exception{
        CaService service = new CaService();
        switch (args[0]){
            case "-init":
                service.init(args[1]);
                break;
            case "-issueCertWithNoP10":
                service.issueCertWithNoP10(args[1]);
                break;
            case "-issueCertWithP10":
                service.issueCertWithP10(true,args[1],args[2],args[3]);
                break;
            case "-issueP12WithNoP10":
                service.issueP12WithNoP10(args[1]);
                break;
            case "help":
            case "-help":
            default:
                System.out.println(help.toString());
                break;

        }
    }
}
