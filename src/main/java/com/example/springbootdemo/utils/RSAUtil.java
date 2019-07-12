package com.example.springbootdemo.utils;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

/**
 * @author: 会跳舞的机器人
 * @date: 2017/9/18 15:00
 * @description: RSA工具类
 */
public class RSAUtil {
  /**
   * 定义加密方式
   */
  private final static String KEY_RSA = "RSA";
  /**
   * 定义签名算法
   */
  private final static String KEY_RSA_SIGNATURE = "MD5withRSA";
  /**
   * 定义公钥算法
   */
  private final static String KEY_RSA_PUBLICKEY = "RSAPublicKey";
  /**
   * 定义私钥算法
   */
  private final static String KEY_RSA_PRIVATEKEY = "RSAPrivateKey";

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * 初始化密钥
   */
  public static Map<String, Object> init() {
    Map<String, Object> map = null;
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_RSA);
      generator.initialize(2048);
      KeyPair keyPair = generator.generateKeyPair();
      // 公钥
      RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
      // 私钥
      RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
      // 将密钥封装为map
      map = new HashMap<>();
      map.put(KEY_RSA_PUBLICKEY, publicKey);
      map.put(KEY_RSA_PRIVATEKEY, privateKey);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return map;
  }

  /**
   * 公钥加密
   *
   * @param data 待加密数据
   * @param key  公钥
   */
  public static byte[] encryptByPublicKey(String data, String key) {
    byte[] result = null;
    try {
      byte[] bytes = decryptBase64(key);
      // 取得公钥
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
      KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
      PublicKey publicKey = factory.generatePublic(keySpec);
      // 对数据加密
      Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");

      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] encode = cipher.doFinal(data.getBytes());
      // 再进行Base64加密
      result = Base64.encode(encode);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return result;
  }

  /**
   * 私钥解密
   *
   * @param data 加密数据
   * @param key  私钥
   */
  public static String decryptByPrivateKey(byte[] data, String key) {
    String result = null;
    try {
      // 对私钥解密
      byte[] bytes = decryptBase64(key);
      // 取得私钥
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
      KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
      PrivateKey privateKey = factory.generatePrivate(keySpec);
      // 对数据解密
      Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      // 先Base64解密
      byte[] decoded = Base64.decode(data);
      result = new String(cipher.doFinal(decoded));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return result;
  }


  /**
   * 获取公钥
   */
  public static String getPublicKey(Map<String, Object> map) {
    String str = "";
    try {
      Key key = (Key) map.get(KEY_RSA_PUBLICKEY);
      str = encryptBase64(key.getEncoded());
    } catch (Exception e) {
      e.printStackTrace();
    }
    return str;
  }

  /**
   * 获取私钥
   */
  public static String getPrivateKey(Map<String, Object> map) {
    String str = "";
    try {
      Key key = (Key) map.get(KEY_RSA_PRIVATEKEY);
      str = encryptBase64(key.getEncoded());
    } catch (Exception e) {
      e.printStackTrace();
    }
    return str;
  }

  /**
   * 用私钥对信息生成数字签名
   *
   * @param data       加密数据
   * @param privateKey 私钥
   */
  public static String sign(byte[] data, String privateKey) {
    String str = "";
    try {
      // 解密由base64编码的私钥
      byte[] bytes = decryptBase64(privateKey);
      // 构造PKCS8EncodedKeySpec对象
      PKCS8EncodedKeySpec pkcs = new PKCS8EncodedKeySpec(bytes);
      // 指定的加密算法
      KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
      // 取私钥对象
      PrivateKey key = factory.generatePrivate(pkcs);
      // 用私钥对信息生成数字签名
      Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);
      signature.initSign(key);
      signature.update(data);
      str = encryptBase64(signature.sign());
    } catch (Exception e) {
      e.printStackTrace();
    }
    return str;
  }

  /**
   * 校验数字签名
   *
   * @param data      加密数据
   * @param publicKey 公钥
   * @param sign      数字签名
   * @return 校验成功返回true，失败返回false
   */
  public static boolean verify(byte[] data, String publicKey, String sign) {
    boolean flag = false;
    try {
      // 解密由base64编码的公钥
      byte[] bytes = decryptBase64(publicKey);
      // 构造X509EncodedKeySpec对象
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
      // 指定的加密算法
      KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
      // 取公钥对象
      PublicKey key = factory.generatePublic(keySpec);
      // 用公钥验证数字签名
      Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);
      signature.initVerify(key);
      signature.update(data);
      flag = signature.verify(decryptBase64(sign));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return flag;
  }


  /**
   * BASE64 解密
   *
   * @param key 需要解密的字符串
   * @return 字节数组
   */
  public static byte[] decryptBase64(String key) throws Exception {
    return Base64.decode(key);
  }

  /**
   * BASE64 加密
   *
   * @param key 需要加密的字节数组
   * @return 字符串
   */
  public static String encryptBase64(byte[] key) throws Exception {
    return new String(Base64.encode(key));
  }


  public static void main(String[] args) throws Exception {
    String publicKey = "";
    String privateKey = "";
    Map<String, Object> keyMap = RSAUtil.init();
    publicKey = RSAUtil.getPublicKey(keyMap);
    privateKey = RSAUtil.getPrivateKey(keyMap);
    System.out.println("公钥：\n\r" + publicKey);
    System.out.println("私钥：\n\r" + privateKey);

    System.out.println("\n\r");
    System.out.println("公钥加密======私钥解密");
    String str = "会跳舞的机器人";
    byte[] enStr = RSAUtil.encryptByPublicKey(str, publicKey);
    String decStr = RSAUtil.decryptByPrivateKey(enStr, privateKey);
    System.out.println("加密前：" + str + "\n\r解密后：" + decStr);

    System.out.println("\n\r");
    System.out.println("私钥签名======公钥验证");
    String sign = RSAUtil.sign(str.getBytes(), privateKey);
    System.out.println("签名：\n\r" + sign);
    boolean flag = RSAUtil.verify(str.getBytes(), publicKey, sign);
    System.out.println("验签结果：\n\r" + flag);
  }
}