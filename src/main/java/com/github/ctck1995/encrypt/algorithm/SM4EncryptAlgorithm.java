package com.github.ctck1995.encrypt.algorithm;

import com.github.ctck1995.util.SM4Util;
import org.apache.shardingsphere.encrypt.strategy.spi.Encryptor;

import java.util.Properties;

/**
 * Created by ck on 2021/3/2.
 * <p/>
 */
public class SM4EncryptAlgorithm implements Encryptor {

    private static final String SM4_KEY = "sm4-key-value";
    private Properties props = new Properties();
    private String key;

    @Override
    public String encrypt(Object plaintext) {
        if (null == plaintext) {
            return null;
        }
        try {
            return SM4Util.encryptEcb(key, String.valueOf(plaintext));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public Object decrypt(String ciphertext) {
        if (null == ciphertext) {
            return null;
        }
        try {
            return SM4Util.decryptEcb(key, ciphertext);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public void init() {
        key = props.getProperty(SM4_KEY);
    }

    @Override
    public String getType() {
        return "SM4";
    }

    @Override
    public Properties getProperties() {
        return this.props;
    }

    @Override
    public void setProperties(Properties properties) {
        this.props = properties;
    }
}
