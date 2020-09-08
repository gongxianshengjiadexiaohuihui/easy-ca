import com.ggp.noob.CaService;
import org.junit.Test;

/**
 * @Author:ggp
 * @Date:2020/8/28 17:13
 * @Description:
 */
public class CertTest {
    @Test
    public void test_p12() throws Exception{
        CaService service = new CaService();
        //service.issueP12WithNoP10("/cert/");
        service.issueCertWithNoP10("/cert");
    }
    @Test
    public void test_inverse_mode(){
        System.out.println(extendedEuclid(9,23));
        System.out.println(extendEuclid(9,23));
        myEuclid(9,23);
    }
    public static int extendEuclid(int e, int modValue){

        int D = 0;
        int x1, x2, x3, y1, y2, y3, temp1, temp2, temp3;

        x1 = y2 = 1;
        x2 = y1= 0;
        x3 = e;
        y3 = modValue;

        int q = 0;
        while(true){
            if(y3 == 1){
                D = y2;
                break;
            }
            if(y3 == 0){
                D = y2;
                break;
            }
            q = x3 / y3;

            temp1 = x1 - q*y1;
            temp2 = x2 - q*y2;
            temp3 = x3 - q*y3;

            x1 = y1;
            x2 = y2;
            x3 = y3;

            y1 = temp1;
            y2 = temp2;
            y3 = temp3;
        }
        return D<0?e+D:D;
    }

    public static int extendedEuclid(int e, int modValue){
        int i;
        int over= e;
        for(i=1; i<modValue; )
        {
            over= over % modValue;
            if( over==1 )
            {
                return i;
            }
            else
            {
                if(over+e<= modValue)
                {
                    do
                    {
                        i++;
                        over += e;
                    }
                    while( over+e <= modValue );
                }
                else
                {
                    i++;
                    over +=e;
                }
            }
        }
        return 0;
    }

    public static void myEuclid(int e, int modValue){
        int num = e;
        int d = 1;
        while((num % modValue ) != 1){
            d++;
            num += e;
        }
        System.out.println(d);
    }

}
