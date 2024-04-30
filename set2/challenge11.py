from secrets import token_bytes, randbelow
from challenge10 import encrypt_aes128_cbc
from challenge9 import pkcs7

import sys
from os import path

sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge7 import __print_block, encrypt_aes128_ecb  # noqa # type: ignore
from challenge8 import find_patterns  # noqa # type: ignore

PATTERN_LENGTH = 2


def random_128() -> bytes:
    return token_bytes(16)


def encrypt_with_random_key(plaintext: bytes):
    # Add 5-10 random bytes to plaintext (start and end)
    plaintext = token_bytes(randbelow(11) + 5) + plaintext + token_bytes(randbelow(11) + 5)

    if randbelow(2):  # 1/2 chance ECB, 1/2 chance CBC
        return ("ECB", encrypt_aes128_ecb(plaintext, random_128()))
    else:
        return ("CBC", encrypt_aes128_cbc(plaintext, random_128(), random_128()))  # Also randomize IV


def detect_aes_mode(data: bytes) -> str:
    return "ECB" if find_patterns(data.hex()) else "CBC"


def test():
    input_ = b"\x69" * 69
    print(f"Input")
    __print_block(pkcs7(input_, 16))

    mode, data = encrypt_with_random_key(input_)
    print(f"Output (actual mode is {mode})")
    __print_block(data)

    detected_mode = detect_aes_mode(data)
    assert (detect_aes_mode(data) == mode)
    print(f"\nOracle says... {detected_mode} !")


if __name__ == "__main__":
    test()
