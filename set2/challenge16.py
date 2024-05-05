from urllib.parse import parse_qsl
from typing import Dict, Set

from challenge10 import encrypt_aes128_cbc, decrypt_aes128_cbc
from challenge11 import random_128

RANDOM_KEY = random_128()


def quote_out(plaintext: bytes, characters: Set[bytes]) -> bytes:
    for c in characters:
        plaintext = plaintext.replace(c, b'"' + c + b'"')

    return plaintext


def cbc_oracle(plaintext: bytes) -> bytes:
    return encrypt_aes128_cbc(
        b"comment1=cooking%20MCs;userdata=" +
        quote_out(plaintext, {b';', b'='}) +
        b";comment2=%20like%20a%20pound%20of%20bacon",
        RANDOM_KEY
    )


def parse_url(url: str) -> Dict:
    return dict(parse_qsl(url, separator=';'))


def is_admin(ciphertext: bytes) -> bool:
    return parse_url(decrypt_aes128_cbc(ciphertext, RANDOM_KEY).decode(errors="backslashreplace")).get("admin", False)


def test():
    assert (
        quote_out(b"comment1=cooking%20MCs;userdata=", {b';', b'='})
        == b"comment1\"=\"cooking%20MCs\";\"userdata\"=\""
    )

    assert (
        parse_url("comment1=cooking%20MCs;userdata=test;comment2=%20like%20a%20pound%20of%20bacon;admin=true;")
        == {
            "comment1": "cooking MCs",
            "userdata": "test",
            "comment2": " like a pound of bacon",
            "admin": "true"
        }
    )

    # Input a full block of data to make 'comment2...' the start of following block
    ciphertext = bytearray(cbc_oracle(b"A" * 15))

    to_replace = ("comment2=%20", ";admin=true;")
    for i in range(len(to_replace[0])):
        # For CBC mode, we have the following:
        # PlaintextBlock[I+1] = XOR(invAes128(CipherBlock[I+1]), CipherBlock[I])
        #
        # We can determine the value of invAes128(CipherBlock[I+1]) by XORing with the plaintext we know ('comment2...')
        # and by the same logic, XOR this value with the plaintext we want in the next block.
        ciphertext[2*16 + i] = ord(to_replace[0][i]) ^ ciphertext[2*16 + i] ^ ord(to_replace[1][i])

    assert (is_admin(ciphertext))

    print(parse_url(decrypt_aes128_cbc(ciphertext, RANDOM_KEY).decode(errors="backslashreplace")))
    print(f"Is admin ? {is_admin(ciphertext)}")


if __name__ == "__main__":
    test()
