import re
from math import ceil

import sys
from os import path

sys.path.insert(0, path.abspath("set4"))

from challenge28 import sha1  # noqa # type: ignore

sys.path.insert(1, path.abspath("set5"))

from challenge39 import i2osp, os2ip, rsa  # noqa # type: ignore
from challenge40 import PQS, find_invpow  # noqa # type: ignore

# Precompute valid RSA keys for speed
USE_PRECOMPUTED_RSA_KEYS = True
# Globals
KEY_SIZE, PUB_KEY, PRIV_KEY, enc, _ = rsa(e=3, pq=PQS[0])
KEY_SIZE_BYTES = ceil(KEY_SIZE / 4)


def emsa_pkcs1_v1_5(message: bytes, emLen: int = KEY_SIZE_BYTES) -> bytes:
    """From https://datatracker.ietf.org/doc/html/rfc8017#section-9.2"""
    H = sha1(message)
    T = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14" + H
    tLen = len(T)

    assert emLen >= tLen + 11, "intended encoded message length too short"

    ps = b'\xff'*(emLen - tLen - 3)
    return b'\x00\x01' + ps + b'\x00' + T


def rsassa_pkcs1_v1_5_sign(message: bytes, private_key: tuple[int, int] = PRIV_KEY) -> bytes:
    """From https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.1"""
    d, n = private_key

    em = emsa_pkcs1_v1_5(message)
    m = os2ip(em)
    s = pow(m, d, n)

    return i2osp(s, KEY_SIZE_BYTES)


def rsassa_pkcs1_v1_5_verify(
    message: bytes,
    signature: bytes,
    public_key: tuple[int, int] = PUB_KEY,
    use_flawed_implementation: bool = True
) -> bool:
    """From https://datatracker.ietf.org/doc/html/rfc8017#section-8.2.2"""
    assert len(signature) == KEY_SIZE_BYTES, "invalid signature"
    e, n = public_key

    s = os2ip(signature)
    assert 0 <= s and s <= n - 1, "signature representative out of range"
    m = pow(s, e, n)
    em = i2osp(m, KEY_SIZE_BYTES)

    zero_byte_index = em.find(b'\x00', 2)
    print(f"[*] Sig: {signature.hex()}")
    print(f"[*] Decrypted: {em.hex()}")
    print(f"[*] Zero byte index: {zero_byte_index}")
    print(f"[*] ASN.1: {em[zero_byte_index+1:zero_byte_index+16].hex()}")
    print(f"[*] Hash: {em[zero_byte_index+16:].hex()}")

    if use_flawed_implementation:
        # Look for the "0x00 0x01 0xFF ... 0xFF ASN.1 HASH" pattern instead of full padding check
        return re.search(r"0001(ff){8,}00[\d\w]+", em.hex()) is not None
    else:
        # Full padding check as per RFC implementation
        return emsa_pkcs1_v1_5(message) == em


def test_signature():
    message = b"YELLOW SUBMARINE"
    signature = rsassa_pkcs1_v1_5_sign(message)

    print(f"[*] Message hash: {sha1(message).hex()}")

    print(f"--- Valid ---")
    assert rsassa_pkcs1_v1_5_verify(message, signature)
    print(f"--- Invalid ---")
    assert not rsassa_pkcs1_v1_5_verify(message, signature[:-1] + b'\xcc')


def test():
    message = b"hi mom"
    forged_signature = i2osp(find_invpow(os2ip(
        b"\x00\x01"
        + b'\xff' * 8
        + b"\x00\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
        + sha1(message)
    ), 3), KEY_SIZE_BYTES)

    print(f"--- Forge ---")
    assert rsassa_pkcs1_v1_5_verify(message, forged_signature)


if __name__ == "__main__":
    test_signature()
    test()
