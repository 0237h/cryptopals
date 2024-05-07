from base64 import b64decode
from secrets import choice

import sys
from os import path
from typing import Tuple

sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge7 import __print_block  # noqa # type: ignore

sys.path.insert(1, path.abspath("set2"))

from challenge9 import pkcs7  # noqa # type: ignore
from challenge10 import encrypt_aes128_cbc, decrypt_aes128_cbc  # noqa # type: ignore
from challenge11 import random_128  # noqa # type: ignore
from challenge15 import validate_pkcs7  # noqa # type: ignore


KEY = random_128()
RANDOM_STRINGS = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]


def cbc_oracle() -> Tuple[bytes, bytes]:
    random_string = choice(RANDOM_STRINGS)
    iv = random_128()
    return (encrypt_aes128_cbc(random_string, KEY, iv), iv)


def is_valid_padding(ciphertext: bytes, iv: bytes) -> bool:
    try:
        validate_pkcs7(decrypt_aes128_cbc(ciphertext, KEY, iv, strip_padding=False))
    except ValueError:
        return False

    return True


def test():
    block_size = 16
    ciphertext, iv = cbc_oracle()
    ciphertext = iv + ciphertext

    # TODO: Investigate recovering padding length first

    n_blocks = len(ciphertext) // block_size - 1
    recovered = bytearray()
    for b in range(n_blocks):
        print(f"[x] Recovering {b+1}/{n_blocks} blocks...", end='\n')
        # Block decryption bytes
        dk = bytearray()
        # Previous block used for discovering plaintext of next block
        c1 = bytearray(ciphertext[b*block_size:(b+1)*block_size])
        # Target plaintext block
        c2 = ciphertext[(b+1)*block_size:(b+2)*block_size]

        for i in range(block_size):
            # Try all possible byte values for each byte of the cipher block to find valid padding plaintexts.
            # Once a valid padding plaintext is found, we extract the block decryption byte and use it to recover the
            # original plaintext.
            for k in range(256):
                c1[-(i+1)] = k

                if (is_valid_padding(c1 + c2, iv)):
                    # Edge case where the decoded plaintext is actually 0x1, messing the padding
                    if (k ^ (i + 1) ^ ciphertext[(b+1)*block_size - 1 - i]) == 0x1:
                        c1[-(i+1)-1] ^= 0x1
                        if not is_valid_padding(c1 + c2, iv):
                            continue

                    dk.append(k ^ (i + 1))
                    recovered.append(dk[-1] ^ ciphertext[(b+1)*block_size - 1 - i])

                    for j in range(i + 1):
                        c1[-(j+1)] = dk[j] ^ (i + 2)  # Set up padding bytes for next iteration (0x1, 0x2 0x2, etc.)
                    break

        # Recovering bytes from last to first requires inverting at the end of the block loop
        recovered[b*block_size:(b+1)*block_size] = recovered[b*block_size:(b+1)*block_size][::-1]

    recovered = validate_pkcs7(recovered)
    print(f"\n[+] Recovered: {recovered}")
    assert (bytes(recovered) in RANDOM_STRINGS)

    print(f"[+] Decoded: {b64decode(recovered)}")


if __name__ == "__main__":
    test()
