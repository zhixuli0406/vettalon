package com.ex;

import javax.crypto.Cipher;

public class Crypto {
    public byte[] seal(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        return c.doFinal(data);
    }
}
