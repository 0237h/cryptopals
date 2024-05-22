from base64 import b64decode

import sys
from os import path
from typing import Literal

sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge7 import _keyExpansion, _aes128  # noqa # type: ignore
from challenge2 import xor  # noqa # type: ignore

sys.path.insert(1, path.abspath("set2"))

from challenge9 import pkcs7  # noqa # type: ignore
from challenge15 import validate_pkcs7  # noqa # type: ignore


def encrypt_aes128_ctr(plaintext: bytes, key: bytes, nonce: bytes | None = None) -> bytearray:
    assert len(key) == 16, "Key must be 128 bits"

    if not nonce:
        nonce = b'\x00' * 8
    assert len(nonce) >= 8, "Nonce must be at least 64 bits"

    keys = _keyExpansion(key)
    nonce = nonce[:8]  # Truncate nonce to 64 bits
    output_bytes = bytearray()
    plaintext = pkcs7(plaintext, 16)

    for i in range(0, len(plaintext), 16):
        output_bytes.extend(
            xor(
                _aes128(nonce + (i // 16).to_bytes(8), keys),
                plaintext[i:i+16]
            )
        )

    return output_bytes


def decrypt_aes128_ctr(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes | None = None,
    strip_padding: bool = True,
    counter_endianness: Literal["little", "big"] = "big"
) -> bytearray:
    assert len(key) == 16, "Key must be 128 bits"

    if not nonce:
        nonce = b'\x00' * 8
    assert len(nonce) >= 8, "Nonce must be at least 64 bits"

    keys = _keyExpansion(key)
    nonce = nonce[:8]  # Truncate nonce to 64 bits
    output_bytes = bytearray()

    for i in range(0, len(ciphertext), 16):
        output_bytes.extend(
            xor(
                _aes128(nonce + (i // 16).to_bytes(8, counter_endianness), keys),
                ciphertext[i:i+16]
            )
        )

    if (strip_padding):
        return validate_pkcs7(output_bytes)

    return output_bytes


def test():
    ciphertext = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    key = b"YELLOW SUBMARINE"

    assert (decrypt_aes128_ctr(ciphertext, key, strip_padding=False, counter_endianness="little") ==
            b"Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ")

    plaintext = b"Hello World!"
    nonce = b'\x69' * 8
    print(f"[*] Plaintext: {plaintext} / Key: {key} / Nonce: {nonce}")

    ciphertext = encrypt_aes128_ctr(plaintext, key, nonce)
    print(f"[*] Encrypted: {ciphertext.hex()}")

    assert (decrypt_aes128_ctr(ciphertext, key, nonce) == plaintext)
    print(f"[+] Decrypted: {decrypt_aes128_ctr(ciphertext, key, nonce)}")


if __name__ == "__main__":
    test()
