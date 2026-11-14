package com.ex;

import java.security.MessageDigest;

public class Unused {
    public byte[] legacy(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
