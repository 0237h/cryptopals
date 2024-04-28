from base64 import b64decode

import sys
from os import path
sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge7 import _keyExpansion, _aes128, _invAes128  # noqa # type: ignore
from challenge2 import xor  # noqa # type: ignore


def encrypt_aes128_cbc(plaintext: bytes, key: bytes, iv: bytes | None = None) -> bytearray:
    assert len(key) == 16, "Key must be 128 bits"

    if not iv:
        iv = b"\x00" * 16

    keys = _keyExpansion(key)
    output_bytes = bytearray(_aes128(xor(plaintext[:16], iv), keys))  # Use IV for first block

    for i in range(16, len(plaintext), 16):
        output_bytes.extend(
            _aes128(
                xor(plaintext[i:i+16], output_bytes[i-16:i]),  # CBC adds previous ciphertext with input of next block
                keys
            )
        )

    return output_bytes


def decrypt_aes128_cbc(ciphertext: bytes, key: bytes, iv: bytes | None = None) -> bytearray:
    assert len(key) == 16, "Key must be 128 bits"

    if not iv:
        iv = b"\x00" * 16

    keys = _keyExpansion(key)
    output_bytes = bytearray(xor(_invAes128(ciphertext[:16], keys), iv))  # Use IV for first block

    for i in range(16, len(ciphertext), 16):
        output_bytes.extend(
            xor(
                _invAes128(ciphertext[i:i+16], keys),
                ciphertext[i-16:i]
            )
        )

    return output_bytes


def test():
    assert (
        encrypt_aes128_cbc(
            bytes.fromhex("6BC1BEE2 2E409F96 E93D7E11 7393172A" +
                          "AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51" +
                          "30C81C46 A35CE411 E5FBC119 1A0A52EF" +
                          "F69F2445 DF4F9B17 AD2B417B E66C3710"),
            bytes.fromhex("2B7E1516 28AED2A6 ABF71588 09CF4F3C"),
            bytes.fromhex("00010203 04050607 08090A0B 0C0D0E0F")
        ) == bytes.fromhex("7649ABAC 8119B246 CEE98E9B 12E9197D" +
                           "5086CB9B 507219EE 95DB113A 917678B2" +
                           "73BED6B8 E3C1743B 7116E69E 22229516" +
                           "3FF1CAA1 681FAC09 120ECA30 7586E1A7")
    )
    # NIST test vectors (https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf)
    assert (
        decrypt_aes128_cbc(
            bytes.fromhex("7649ABAC 8119B246 CEE98E9B 12E9197D" +
                          "5086CB9B 507219EE 95DB113A 917678B2" +
                          "73BED6B8 E3C1743B 7116E69E 22229516" +
                          "3FF1CAA1 681FAC09 120ECA30 7586E1A7"),
            bytes.fromhex("2B7E1516 28AED2A6 ABF71588 09CF4F3C"),
            bytes.fromhex("00010203 04050607 08090A0B 0C0D0E0F")
        ) == bytes.fromhex("6BC1BEE2 2E409F96 E93D7E11 7393172A" +
                           "AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51" +
                           "30C81C46 A35CE411 E5FBC119 1A0A52EF" +
                           "F69F2445 DF4F9B17 AD2B417B E66C3710")
    )

    cipherfile = open("./set2/challenge_10.txt", "rb").read()
    key = "YELLOW SUBMARINE"
    recovered_cipherfile = decrypt_aes128_cbc(b64decode(cipherfile), key.encode()).decode()

    assert (recovered_cipherfile[:33] == "I'm back and I'm ringin' the bell")
    print(recovered_cipherfile)


if __name__ == "__main__":
    test()
