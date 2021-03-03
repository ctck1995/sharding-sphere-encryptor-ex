package com.github.ctck1995.util;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Arrays;

/**
 * Created by ck on 2021/3/2.
 * <p/>
 */
public class SM4Util {

    private static final String ENCODING = "UTF-8";
    private static final String ALGORIGTHM_NAME = "SM4";
    private static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS7Padding";
    private static final int DEFAULT_KEY_SIZE = 128;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成ecb暗号
     *
     * @param algorithmName
     * @param mode
     * @param key
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    private static Cipher generateEcbCipher(String algorithmName, int mode, byte[] key) throws NoSuchPaddingException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, ALGORIGTHM_NAME);
        cipher.init(mode, sm4Key);
        return cipher;
    }

    /**
     * 自动生成密钥
     *
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] generateKey() throws NoSuchProviderException, NoSuchAlgorithmException {
        return generateKey(DEFAULT_KEY_SIZE);
    }

    /**
     * 自动生成密钥
     *
     * @param keySize
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] generateKey(int keySize) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORIGTHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }

    /**
     * 加密
     *
     * @param hexKey
     * @param paramStr
     * @param charset
     * @return
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public static String encryptEcb(String hexKey, String paramStr) throws UnsupportedEncodingException,
            NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            NoSuchProviderException, InvalidKeyException {
        return encryptEcb(hexKey, paramStr, ENCODING);
    }

    /**
     * 加密
     *
     * @param hexKey
     * @param paramStr
     * @param charset
     * @return
     * @throws UnsupportedEncodingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public static String encryptEcb(String hexKey, String paramStr, String charset) throws UnsupportedEncodingException,
            NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            NoSuchProviderException, InvalidKeyException {
        if (null != paramStr && !"".equals(paramStr)) {
            byte[] keyData = ByteUtils.fromHexString(hexKey);
            charset = charset.trim();
            if (charset.length() <= 0) {
                charset = ENCODING;
            }
            byte[] srcData = paramStr.getBytes(charset);
            return Base64.encodeBase64String(encrypt_Ecb_Padding(keyData, srcData));
        }
        return null;
    }

    /**
     * 加密模式之ecb
     *
     * @param key
     * @param data
     * @return
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] encrypt_Ecb_Padding(byte[] key, byte[] data) throws NoSuchProviderException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    /**
     * 解密
     *
     * @param hexKey
     * @param cipherText
     * @param charset
     * @return
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public static String decryptEcb(String hexKey, String cipherText) throws BadPaddingException,
            IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException,
            NoSuchPaddingException, NoSuchProviderException, InvalidKeyException {
        return decryptEcb(hexKey, cipherText, ENCODING);
    }

    /**
     * 解密
     *
     * @param hexKey
     * @param cipherText
     * @param charset
     * @return
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public static String decryptEcb(String hexKey, String cipherText, String charset) throws BadPaddingException,
            IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException,
            NoSuchPaddingException, NoSuchProviderException, InvalidKeyException {
        byte[] keyData = ByteUtils.fromHexString(hexKey);
        byte[] cipherData = Base64.decodeBase64(cipherText);
        byte[] srcData = decrypt_Ecb_Padding(keyData, cipherData);
        charset = charset.trim();
        if (charset.length() <= 0) {
            charset = ENCODING;
        }
        return new String(srcData, charset);
    }

    /**
     * 解密
     *
     * @param key
     * @param cipherText
     * @return
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    public static byte[] decrypt_Ecb_Padding(byte[] key, byte[] cipherText) throws BadPaddingException,
            IllegalBlockSizeException, NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException {
        Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    /**
     * 密码校验
     *
     * @param hexKey
     * @param cipherText
     * @param paramStr
     * @return
     * @throws UnsupportedEncodingException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     */
    public static boolean verifyEcb(String hexKey, String cipherText, String paramStr) throws UnsupportedEncodingException,
            BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException,
            NoSuchProviderException, InvalidKeyException {
        byte[] keyData = ByteUtils.fromHexString(hexKey);
        byte[] cipherData = Base64.decodeBase64(cipherText);
        byte[] decryptData = decrypt_Ecb_Padding(keyData, cipherData);
        byte[] srcData = paramStr.getBytes(ENCODING);
        return Arrays.equals(decryptData, srcData);
    }

    public static void main(String[] args) throws Exception {
        String content = "3277238213791hwequeyqwuiyeyi23713791ewiheqii31";
        // 自定义的32位16进制密钥
        String key = "cc9368581322479ebf3e79348a2757d9";
        String cipher = SM4Util.encryptEcb(key, content);
        System.out.println(cipher);
        System.out.println(SM4Util.verifyEcb(key, cipher, content));
        content = SM4Util.decryptEcb(key, cipher);
        System.out.println(content);
    }
}
