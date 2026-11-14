package com.ex;

public class Main {
    public static void main(String[] args) throws Exception {
        byte[] sealed = new Crypto().seal(new byte[16]);
        System.out.println(sealed.length);
    }
}
