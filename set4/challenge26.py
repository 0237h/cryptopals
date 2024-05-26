import sys
from os import path

sys.path.insert(1, path.abspath("set2"))  # Python hack to resolve set2/ challenges imports

from challenge11 import random_128  # noqa # type: ignore

sys.path.insert(1, path.abspath("set3"))  # Python hack to resolve set3/ challenges imports

from challenge16 import parse_url, quote_out  # noqa # type: ignore
from challenge18 import encrypt_aes128_ctr, decrypt_aes128_ctr  # noqa # type: ignore

RANDOM_KEY = random_128()


def ctr_oracle(plaintext: bytes) -> bytes:
    return encrypt_aes128_ctr(
        b"comment1=cooking%20MCs;userdata=" +
        quote_out(plaintext, {b';', b'='}) +
        b";comment2=%20like%20a%20pound%20of%20bacon",
        RANDOM_KEY
    )


def is_admin(ciphertext: bytes) -> bool:
    return parse_url(decrypt_aes128_ctr(ciphertext, RANDOM_KEY).decode(errors="backslashreplace")).get("admin", False)


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
    ciphertext = bytearray(ctr_oracle(b"MightyAccountXY"))

    to_replace = ("comment2=%20", ";admin=true;")
    for i in range(len(to_replace[0])):
        # For CTR mode, we have the following:
        # Pn = Cn ^ AES(nonce + (n-1), K)
        #
        # To replace with the text we want (P'n), we can just choose Cn such that:
        # Cn = Pn ^ Cn ^ P'n
        #
        # Leaving us with:
        # Pn = (Pn ^ Cn ^ P'n) ^ AES(nonce + (n-1), K)
        #    = P'n ^ Pn ^ (Cn ^ AES(nonce + (n-1), K))
        #    = P'n ^ Pn ^ Pn
        #    = P'n
        ciphertext[3*16 + i] = ord(to_replace[0][i]) ^ ciphertext[3*16 + i] ^ ord(to_replace[1][i])

    assert (is_admin(ciphertext))

    print(parse_url(decrypt_aes128_ctr(ciphertext, RANDOM_KEY).decode(errors="backslashreplace")))
    print(f"Is admin ? {is_admin(ciphertext)}")


if __name__ == "__main__":
    test()
