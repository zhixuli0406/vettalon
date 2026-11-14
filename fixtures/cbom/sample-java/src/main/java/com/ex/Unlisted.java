package com.ex;

import java.security.MessageDigest;

public class Unlisted {
    public byte[] checksum(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }
}
