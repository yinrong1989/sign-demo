package cn.nflow.nfsp.util;

import com.alibaba.fastjson.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;


public class RSATool {

    Log log = LogFactory.getLog(RSATool.class);
    private static final String KEY_ALGORITHM = "RSA";

    private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
    static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

    static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

    static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

    public String signWith(PrivateKey privateKey, byte[] binData) {
        try {
            //SHA1withRSA算法进行签名
            Signature sign = Signature.getInstance(SIGNATURE_ALGORITHM);
            sign.initSign(privateKey);
            sign.update(binData);
            byte[] signature = sign.sign();
            return Base64.encodeBase64String(signature);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean veryfyWith(PublicKey publicKey, byte[] binData, byte[] signed) {

        try {
            if (signed.length == 0) {
                log.warn("veryfy sign prompt:The sign is empty,warning");
                return true;
            }
            Signature verifySign = Signature.getInstance(SIGNATURE_ALGORITHM);
            verifySign.initVerify(publicKey);
            verifySign.update(binData);
            return verifySign.verify(signed);
        } catch (InvalidKeyException e) {
            log.warn(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            log.warn(e.getMessage());
        } catch (SignatureException e) {
            log.warn(e.getMessage());
        }
        return false;
    }

    public PublicKey loadPublicKeyFrom(String pemPath) {
        try {
            InputStream input = getClass().getResourceAsStream(pemPath);
            byte[] temp = new byte[input.available()];
            input.read(temp);
            input.close();
            String fileb64 = new String(temp);
            fileb64 = fileb64.replace(BEGIN_PUBLIC_KEY, "").replace(END_PUBLIC_KEY, "");
            //System.out.println(fileb64);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            byte[] decodeByte = Base64.decodeBase64(fileb64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodeByte);
            return keyFactory.generatePublic(keySpec);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public PublicKey loadPublicKeyWith(String keyString) {
        try {
            String fileb64 = new String(keyString);
            fileb64 = fileb64.replace(BEGIN_PUBLIC_KEY, "").replace(END_PUBLIC_KEY, "");
            //System.out.println(fileb64);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] decodeByte = Base64.decodeBase64(fileb64);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodeByte);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public PrivateKey loadPrivateKeyFrom(String pemPath) {
        try {
            InputStream input = getClass().getResourceAsStream(pemPath);
            byte[] temp = new byte[input.available()];
            input.read(temp);
            input.close();
            String fileb64 = new String(temp);
            fileb64 = fileb64.replace(BEGIN_PRIVATE_KEY, "").replace(END_PRIVATE_KEY, "");
            //System.out.println(fileb64);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] decodeByte = Base64.decodeBase64(fileb64);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodeByte);
            return keyFactory.generatePrivate(keySpec);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public PrivateKey loadPrivateKeyWith(String keyString) {
        try {
            String fileb64 = new String(keyString);
            fileb64 = fileb64.replace(BEGIN_PRIVATE_KEY, "").replace(END_PRIVATE_KEY, "");
            //System.out.println(fileb64);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] decodeByte = Base64.decodeBase64(fileb64);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodeByte);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String encryptToBase64(PublicKey publicKey,byte[] plainText){
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return Base64.encodeBase64String(cipher.doFinal(plainText));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    public String decryptFromBase64(PrivateKey privateKey,byte[] base64Text){
        try {
            base64Text=Base64.decodeBase64(base64Text);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(cipher.doFinal(base64Text));
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Map<String,String> generatePaireKey(int length){
        KeyPairGenerator generator= null;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(length);
            KeyPair keyPair = generator.generateKeyPair();
            final PublicKey aPublic = keyPair.getPublic();
            final PrivateKey aPrivate = keyPair.getPrivate();
            Map<String,String> paire=new HashMap<>();
            paire.put("private",Base64.encodeBase64String(aPrivate.getEncoded()));
            paire.put("public",Base64.encodeBase64String(aPublic.getEncoded()));
            return paire;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    public static Map<String,String> generatePaireKey(int length,String algorithm){
        KeyPairGenerator generator= null;
        try {
            generator = KeyPairGenerator.getInstance(algorithm);
            generator.initialize(length);
            KeyPair keyPair = generator.generateKeyPair();
            final PublicKey aPublic = keyPair.getPublic();
            final PrivateKey aPrivate = keyPair.getPrivate();
            Map<String,String> paire=new HashMap<>();
            paire.put("private",Base64.encodeBase64String(aPrivate.getEncoded()));
            paire.put("public",Base64.encodeBase64String(aPublic.getEncoded()));
            return paire;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64.decodeBase64(sign));
    }
    public static boolean verify(String data, String publicKey, String sign) throws Exception {
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        return verify(dataBytes, publicKey, sign);
    }
    public static String sign(String data, String privateKey) throws Exception {
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        return sign(dataBytes, privateKey);
    }
    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64.encodeBase64String(signature.sign());
    }
    public static void main(String[] args) {

        System.out.println(JSONObject.toJSONString(generatePaireKey(2048,"RSA")));
    }
}
