import sys
from os import path

sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge2 import xor  # noqa # type: ignore
from challenge7 import __print_block  # noqa # type: ignore

sys.path.insert(1, path.abspath("set2"))  # Python hack to resolve set2/ challenges imports

from challenge11 import random_128  # noqa # type: ignore

sys.path.insert(1, path.abspath("set3"))  # Python hack to resolve set3/ challenges imports

from challenge10 import encrypt_aes128_cbc, decrypt_aes128_cbc  # noqa # type: ignore
from challenge16 import parse_url, quote_out  # noqa # type: ignore

RANDOM_KEY = random_128()
print(f"[*] Target key:\n{RANDOM_KEY.hex()}")


def verify_plaintext(plaintext: bytes) -> bytes:
    # Accept ASCII between 32 and 126
    # https://en.wikipedia.org/wiki/ASCII#Printable_characters
    if any((k for k in plaintext if k < 32 or k > 126)):
        raise ValueError("Only ASCII printable characters (32 to 126) allowed")

    return plaintext


def cbc_oracle(plaintext: bytes) -> bytes:
    return encrypt_aes128_cbc(
        b"comment1=cooking%20MCs;userdata=" +
        quote_out(plaintext, {b';', b'='}) +
        b";comment2=%20like%20a%20pound%20of%20bacon",
        RANDOM_KEY,
        iv=RANDOM_KEY  # Using key as IV
    )


def decrypt_verify(ciphertext: bytes) -> str:
    plaintext = decrypt_aes128_cbc(ciphertext, RANDOM_KEY, iv=RANDOM_KEY)

    try:
        return parse_url(verify_plaintext(plaintext).decode(errors="backslashreplace"))
    except ValueError as e:
        raise RuntimeError(f"Decrypted:\n{plaintext}") from e


def test_verify():
    assert verify_plaintext(b"Hello") == b"Hello"
    try:
        verify_plaintext(b"Hello" + bytes("Œ", encoding='utf-8'))
        assert False, "Failed to raise exception on non-printable ASCII"
    except ValueError as e:
        assert str(e) == "Only ASCII printable characters (32 to 126) allowed"

    try:
        print(decrypt_verify(cbc_oracle(bytes("ŒHello World!", encoding='utf-8'))))
    except RuntimeError as e:
        assert "\\xc5\\x92Hello World!" in str(e)


def test():
    block_size = 16
    ciphertext = bytearray(cbc_oracle(b''))

    # Ciphertext is at least 3 blocks: C1, C2, C3
    print("[*] Ciphertext:")
    __print_block(ciphertext)

    # Reorganize ciphertext so that we have: C1, 0, C1
    ciphertext[block_size:2*block_size] = b"\x00" * block_size
    ciphertext[2*block_size:3*block_size] = ciphertext[:block_size]
    print("[*] Cutted ciphertext:")
    __print_block(ciphertext)

    # Now, when we decrypt we get:
    # P1 = invAES(C1) ^ IV
    # P2 = invAES(0) ^ C1
    # P3 = invAES(C1) ^ 0
    #
    # P1 ^ P3 = IV ^ 0 = IV
    #
    # Since IV = Key here, we just recovered the key !
    try:
        decrypt_verify(ciphertext)
    except RuntimeError as e:
        decrypted = eval(str(e).split('\n')[-1])
        recovered_key = xor(decrypted[:block_size], decrypted[2*block_size:3*block_size])

        assert recovered_key == RANDOM_KEY
        print(f"[+] Recovered key:\n{recovered_key.hex()}")


if __name__ == "__main__":
    test_verify()
    test()
