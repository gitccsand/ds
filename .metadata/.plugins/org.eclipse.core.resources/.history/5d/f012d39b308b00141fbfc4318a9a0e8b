package testmd5;

import java.security.MessageDigest;

public class TestMD5 {

	public final static String MD5(String s) {
        char hexDigits[]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};       
        try {
            byte[] btInput = s.getBytes();
            // 获得MD5摘要算法的 MessageDigest 对象
            MessageDigest mdInst = MessageDigest.getInstance("MD5");
            // 使用指定的字节更新摘要
            mdInst.update(btInput);
            // 获得密文
            byte[] md = mdInst.digest();
            // 把密文转换成十六进制的字符串形式
            char str[] = new char[md.length * 2];
            int k = 0;
            for (int i = 0; i < md.length; i++) {
                byte byte0 = md[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            return new String(str);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public static void main(String[] args) {
    	System.out.println("9823483984032 摘要：");
        System.out.println(TestMD5.MD5("9823483984032"));
        System.out.println("炼数成金 摘要：");
        System.out.println(TestMD5.MD5("炼数成金"));
    }
}
