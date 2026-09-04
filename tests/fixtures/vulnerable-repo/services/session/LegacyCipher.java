package com.bharatpay.session;

import javax.crypto.Cipher;
import java.security.MessageDigest;

public class LegacyCipher {
    // legacy session store — AES-128 in CBC mode
    public byte[] encrypt(byte[] data, javax.crypto.SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data);
    }

    public byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
}
