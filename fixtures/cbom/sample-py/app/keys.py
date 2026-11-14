from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def make_signing_key():
    # reachable: called from main()
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def legacy_ecdsa_key():
    # unreachable: never called
    return ec.generate_private_key(ec.SECP256R1())


def encrypt(data: bytes) -> bytes:
    key = AESGCM.generate_key(bit_length=256)
    return AESGCM(key).encrypt(b"0" * 12, data, None)


def sign(key, msg: bytes) -> bytes:
    return key.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
