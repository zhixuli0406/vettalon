//! Fixed BouncyCastle lightweight API inventory; no constructor inference.
pub(super) fn lookup(class: &str) -> Option<(Option<&'static str>, Option<&'static str>)> {
    let algorithm = match class {
        "AESEngine" | "AESFastEngine" | "AESLightEngine" => "AES",
        "DESEngine" => "DES",
        "DESedeEngine" => "DESede",
        "BlowfishEngine" => "Blowfish",
        "TwofishEngine" => "Twofish",
        "ChaChaEngine" => "ChaCha",
        "ChaCha7539Engine" => "ChaCha20",
        "Salsa20Engine" => "Salsa20",
        "RC4Engine" => "RC4",
        "RSAEngine" | "RSAKeyPairGenerator" | "RSADigestSigner" | "PSSSigner" => "RSA",
        "ElGamalEngine" => "ElGamal",
        "SHA1Digest" => "SHA-1",
        "SHA224Digest" => "SHA-224",
        "SHA256Digest" => "SHA-256",
        "SHA384Digest" => "SHA-384",
        "SHA512Digest" => "SHA-512",
        "SHA3Digest" => "SHA-3",
        "MD5Digest" => "MD5",
        "MD4Digest" => "MD4",
        "RIPEMD160Digest" => "RIPEMD-160",
        "Blake2bDigest" => "BLAKE2b",
        "HMac" => "HMAC",
        "CMac" => "CMAC",
        "ECDSASigner" => "ECDSA",
        "DSASigner" => "DSA",
        "Ed25519Signer" | "Ed25519KeyPairGenerator" => "Ed25519",
        "Ed448Signer" => "Ed448",
        "ECKeyPairGenerator" => "EC",
        "DHKeyPairGenerator" => "DH",
        "X25519Agreement" => "X25519",
        "ECDHBasicAgreement" => "ECDH",
        "MLKEMKeyPairGenerator" | "MLKEMGenerator" => "ML-KEM",
        "MLDSASigner" | "MLDSAKeyPairGenerator" => "ML-DSA",
        "SLHDSASigner" => "SLH-DSA",
        "ChaCha20Poly1305" => "ChaCha20-Poly1305",
        mode => {
            return Some((
                None,
                Some(match mode {
                    "GCMBlockCipher" => "GCM",
                    "CBCBlockCipher" => "CBC",
                    "CTRBlockCipher" | "SICBlockCipher" => "CTR",
                    "CCMBlockCipher" => "CCM",
                    "OCBBlockCipher" => "OCB",
                    _ => return None,
                }),
            ));
        }
    };
    Some((Some(algorithm), None))
}
