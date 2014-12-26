package testrsa;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class RSAUtils {  
	  
    /** *//** 
     * 加密算法RSA 
     */  
    public static final String KEY_ALGORITHM = "RSA";  
      
    
    
    /**  
    * BASE64解密  
    *   
    * @param key  
    * @return  
    * @throws Exception  
    */    
    public static byte[] decryptBASE64(String key) throws Exception {    
        return (new BASE64Decoder()).decodeBuffer(key);    
    }    
    /**  
    * BASE64加密  
    *   
    * @param key  
    * @return  
    * @throws Exception  
    */    
    public static String encryptBASE64(byte[] key) throws Exception {    
        return (new BASE64Encoder()).encodeBuffer(key);    
    }    
  
   
    /**  
     * 加密  
     * @param privateKey  
     * @param srcBytes  
     * @return  
     * @throws NoSuchAlgorithmException  
     * @throws NoSuchPaddingException  
     * @throws InvalidKeyException  
     * @throws IllegalBlockSizeException  
     * @throws BadPaddingException  
     */    
    protected byte[] encrypt(RSAPrivateKey privateKey,byte[] srcBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{    
        if(privateKey!=null){    
            //Cipher负责完成加密或解密工作，基于RSA    
            Cipher cipher = Cipher.getInstance("RSA");    
            //根据公钥，对Cipher对象进行初始化    
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);    
            byte[] resultBytes = cipher.doFinal(srcBytes);    
            return resultBytes;    
        }    
        return null;    
    }    
        
    /**  
     * 解密   
     * @param publicKey  
     * @param srcBytes  
     * @return  
     * @throws NoSuchAlgorithmException  
     * @throws NoSuchPaddingException  
     * @throws InvalidKeyException  
     * @throws IllegalBlockSizeException  
     * @throws BadPaddingException  
     */    
    protected byte[] decrypt(RSAPublicKey publicKey,byte[] srcBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{    
        if(publicKey!=null){    
            //Cipher负责完成加密或解密工作，基于RSA    
            Cipher cipher = Cipher.getInstance("RSA");    
            //根据公钥，对Cipher对象进行初始化    
            cipher.init(Cipher.DECRYPT_MODE, publicKey);    
            byte[] resultBytes = cipher.doFinal(srcBytes);    
            return resultBytes;    
        }    
        return null;    
    }    
    
    /**  
     * @param args  
     * @throws NoSuchAlgorithmException   
     * @throws BadPaddingException   
     * @throws IllegalBlockSizeException   
     * @throws NoSuchPaddingException   
     * @throws InvalidKeyException   
     */    
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException ,Exception{    
    	RSAUtils rsa = new RSAUtils();    
        String msg = "<span style="+"font-family: Arial, Helvetica, sans-serif;"+">公钥和私钥</span>";    
        //KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象    
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");    
        //初始化密钥对生成器，密钥大小为1024位    
        keyPairGen.initialize(1024);    
        //生成一个密钥对，保存在keyPair中    
        KeyPair keyPair = keyPairGen.generateKeyPair();    
        //得到私钥    
        RSAPrivateKey rsaPirvateKey = (RSAPrivateKey)keyPair.getPrivate();                 
        //得到公钥    
        RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();    
            
          
          
        byte[] publicKeybyte =rsaPublicKey.getEncoded();  
        String publicKeyString = encryptBASE64(publicKeybyte);  
        System.out.println(publicKeyString);  
          
        byte[] privateKeybyte =rsaPirvateKey.getEncoded();  
        String privateKeyString = encryptBASE64(privateKeybyte);  
        System.out.println(privateKeyString);  
          
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);    
        PKCS8EncodedKeySpec privatekcs8KeySpec = new PKCS8EncodedKeySpec(decryptBASE64(privateKeyString));    
        PrivateKey privateKey= keyFactory.generatePrivate(privatekcs8KeySpec);            
   
          
        X509EncodedKeySpec publicpkcs8KeySpec = new X509EncodedKeySpec(decryptBASE64(publicKeyString));   
        PublicKey publicKey = keyFactory.generatePublic(publicpkcs8KeySpec);  
                  
          
        //用私钥加密    
        byte[] srcBytes = msg.getBytes();    
        byte[] resultBytes = rsa.encrypt((RSAPrivateKey)privateKey, srcBytes);    
          
        String base64Msg= encryptBASE64(resultBytes);  
          
        byte[] base64MsgD = decryptBASE64(base64Msg);  
            
        //用公钥解密    
        byte[] decBytes = rsa.decrypt((RSAPublicKey) publicKey, base64MsgD);    
            
        System.out.println("明文是:" + msg);    
        System.out.println("双重加密后是:" +base64Msg);    
        System.out.println("解密后是:" + new String(decBytes));    
    }    
 
}


///** *//** 
// * 加密算法RSA 
// */  
//public static final String KEY_ALGORITHM = "RSA";  
///** *//** 
// * 签名算法 
// */  
//public static final String SIGNATURE_ALGORITHM = "MD5withRSA";  
//
///** *//** 
// * 获取公钥的key 
// */  
//private static final String PUBLIC_KEY = "RSAPublicKey";  
//  
///** *//** 
// * 获取私钥的key 
// */  
//private static final String PRIVATE_KEY = "RSAPrivateKey";  
//  
///** *//** 
// * RSA最大加密明文大小 
// */  
//private static final int MAX_ENCRYPT_BLOCK = 117;  
//  
///** *//** 
// * RSA最大解密密文大小 
// */  
//private static final int MAX_DECRYPT_BLOCK = 128;  
/** *//** 
 * <p> 
 * 生成密钥对(公钥和私钥) 
 * </p> 
 *  
 * @return 
 * @throws Exception 
 */  
//public static Map<String, Object> genKeyPair() throws Exception {  
//    KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);  
//    keyPairGen.initialize(1024);  
//    KeyPair keyPair = keyPairGen.generateKeyPair();  
//    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  
//    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();  
//    Map<String, Object> keyMap = new HashMap<String, Object>(2);  
//    keyMap.put(PUBLIC_KEY, publicKey);  
//    keyMap.put(PRIVATE_KEY, privateKey);  
//    return keyMap;  
//}  
//    /** *//** 
//     * <p> 
//     * 用私钥对信息生成数字签名 
//     * </p> 
//     *  
//     * @param data 已加密数据 
//     * @param privateKey 私钥(BASE64编码) 
//     *  
//     * @return 
//     * @throws Exception 
//     */  
//    public static String sign(byte[] data, String privateKey) throws Exception {  
//    	
//        byte[] keyBytes = Base64Utils.decode(privateKey);  
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
//        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);  
//        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);  
//        signature.initSign(privateK);  
//        signature.update(data);  
//        return Base64Utils.encode(signature.sign());  
//    }  
//  
//    /** *//** 
//     * <p> 
//     * 校验数字签名 
//     * </p> 
//     *  
//     * @param data 已加密数据 
//     * @param publicKey 公钥(BASE64编码) 
//     * @param sign 数字签名 
//     *  
//     * @return 
//     * @throws Exception 
//     *  
//     */  
//    public static boolean verify(byte[] data, String publicKey, String sign)  
//            throws Exception {  
//        byte[] keyBytes = Base64Utils.decode(publicKey);  
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);  
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
//        PublicKey publicK = keyFactory.generatePublic(keySpec);  
//        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);  
//        signature.initVerify(publicK);  
//        signature.update(data);  
//        return signature.verify(Base64Utils.decode(sign));  
//    }  
//  
//    /** *//** 
//     * <P> 
//     * 私钥解密 
//     * </p> 
//     *  
//     * @param encryptedData 已加密数据 
//     * @param privateKey 私钥(BASE64编码) 
//     * @return 
//     * @throws Exception 
//     */  
//    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey)  
//            throws Exception {  
//        byte[] keyBytes = Base64Utils.decode(privateKey);  
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
//        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);  
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  
//        cipher.init(Cipher.DECRYPT_MODE, privateK);  
//        int inputLen = encryptedData.length;  
//        ByteArrayOutputStream out = new ByteArrayOutputStream();  
//        int offSet = 0;  
//        byte[] cache;  
//        int i = 0;  
//        // 对数据分段解密  
//        while (inputLen - offSet > 0) {  
//            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {  
//                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);  
//            } else {  
//                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);  
//            }  
//            out.write(cache, 0, cache.length);  
//            i++;  
//            offSet = i * MAX_DECRYPT_BLOCK;  
//        }  
//        byte[] decryptedData = out.toByteArray();  
//        out.close();  
//        return decryptedData;  
//    }  
//  
//    /** *//** 
//     * <p> 
//     * 公钥解密 
//     * </p> 
//     *  
//     * @param encryptedData 已加密数据 
//     * @param publicKey 公钥(BASE64编码) 
//     * @return 
//     * @throws Exception 
//     */  
//    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey)  
//            throws Exception {  
//        byte[] keyBytes = Base64Utils.decode(publicKey);  
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);  
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
//        Key publicK = keyFactory.generatePublic(x509KeySpec);  
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  
//        cipher.init(Cipher.DECRYPT_MODE, publicK);  
//        int inputLen = encryptedData.length;  
//        ByteArrayOutputStream out = new ByteArrayOutputStream();  
//        int offSet = 0;  
//        byte[] cache;  
//        int i = 0;  
//        // 对数据分段解密  
//        while (inputLen - offSet > 0) {  
//            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {  
//                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);  
//            } else {  
//                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);  
//            }  
//            out.write(cache, 0, cache.length);  
//            i++;  
//            offSet = i * MAX_DECRYPT_BLOCK;  
//        }  
//        byte[] decryptedData = out.toByteArray();  
//        out.close();  
//        return decryptedData;  
//    }  
//  
//    /** *//** 
//     * <p> 
//     * 公钥加密 
//     * </p> 
//     *  
//     * @param data 源数据 
//     * @param publicKey 公钥(BASE64编码) 
//     * @return 
//     * @throws Exception 
//     */  
//    public static byte[] encryptByPublicKey(byte[] data, String publicKey)  
//            throws Exception {  
//        byte[] keyBytes = Base64Utils.decode(publicKey);  
//        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);  
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
//        Key publicK = keyFactory.generatePublic(x509KeySpec);  
//        // 对数据加密  
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  
//        cipher.init(Cipher.ENCRYPT_MODE, publicK);  
//        int inputLen = data.length;  
//        ByteArrayOutputStream out = new ByteArrayOutputStream();  
//        int offSet = 0;  
//        byte[] cache;  
//        int i = 0;  
//        // 对数据分段加密  
//        while (inputLen - offSet > 0) {  
//            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {  
//                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);  
//            } else {  
//                cache = cipher.doFinal(data, offSet, inputLen - offSet);  
//            }  
//            out.write(cache, 0, cache.length);  
//            i++;  
//            offSet = i * MAX_ENCRYPT_BLOCK;  
//        }  
//        byte[] encryptedData = out.toByteArray();  
//        out.close();  
//        return encryptedData;  
//    }  
//  
//    /** *//** 
//     * <p> 
//     * 私钥加密 
//     * </p> 
//     *  
//     * @param data 源数据 
//     * @param privateKey 私钥(BASE64编码) 
//     * @return 
//     * @throws Exception 
//     */  
//    public static byte[] encryptByPrivateKey(byte[] data, String privateKey)  
//            throws Exception {  
//        byte[] keyBytes = Base64Utils.decode(privateKey);  
//        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
//        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
//        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);  
//        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  
//        cipher.init(Cipher.ENCRYPT_MODE, privateK);  
//        int inputLen = data.length;  
//        ByteArrayOutputStream out = new ByteArrayOutputStream();  
//        int offSet = 0;  
//        byte[] cache;  
//        int i = 0;  
//        // 对数据分段加密  
//        while (inputLen - offSet > 0) {  
//            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {  
//                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);  
//            } else {  
//                cache = cipher.doFinal(data, offSet, inputLen - offSet);  
//            }  
//            out.write(cache, 0, cache.length);  
//            i++;  
//            offSet = i * MAX_ENCRYPT_BLOCK;  
//        }  
//        byte[] encryptedData = out.toByteArray();  
//        out.close();  
//        return encryptedData;  
//    }  
//  
//    /** *//** 
//     * <p> 
//     * 获取私钥 
//     * </p> 
//     *  
//     * @param keyMap 密钥对 
//     * @return 
//     * @throws Exception 
//     */  
//    public static String getPrivateKey(Map<String, Object> keyMap)  
//            throws Exception {  
//        Key key = (Key) keyMap.get(PRIVATE_KEY);  
//        return Base64Utils.encode(key.getEncoded());  
//    }  
//  
//    /** *//** 
//     * <p> 
//     * 获取公钥 
//     * </p> 
//     *  
//     * @param keyMap 密钥对 
//     * @return 
//     * @throws Exception 
//     */  
//    public static String getPublicKey(Map<String, Object> keyMap)  
//            throws Exception {  
//        Key key = (Key) keyMap.get(PUBLIC_KEY);  
//        return Base64Utils.encode(key.getEncoded());  
//    }  
  
