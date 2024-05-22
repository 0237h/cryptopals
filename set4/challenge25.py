from base64 import b64decode

import sys
from os import path

sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge2 import xor  # noqa # type: ignore
from challenge7 import decrypt_aes128_ecb  # noqa # type: ignore

sys.path.insert(1, path.abspath("set2"))

from challenge11 import random_128  # noqa # type: ignore
from challenge15 import validate_pkcs7  # noqa # type: ignore

sys.path.insert(1, path.abspath("set3"))  # Python hack to resolve set3/ challenges imports

from challenge18 import encrypt_aes128_ctr, decrypt_aes128_ctr  # noqa # type: ignore

RANDOM_KEY = random_128()
RANDOM_IV = random_128()


def edit(ciphertext: bytes, key: bytes, offset: int, plaintext: bytes) -> bytes:
    assert (offset >= 0)

    if (offset >= len(ciphertext)):
        offset = len(ciphertext)

    temp_plaintext = decrypt_aes128_ctr(ciphertext, key, RANDOM_IV)

    return encrypt_aes128_ctr(temp_plaintext[:offset] + plaintext + temp_plaintext[offset:], key, RANDOM_IV)


def API_edit(ciphertext: bytes, offset: int, plaintext: bytes) -> bytes:
    return edit(ciphertext, RANDOM_KEY, offset, plaintext)


# Let Cn = Pn ^ AES(nonce + (n-1), K) the cipher block n (with Pn the corresponding plaintext block)
#
# When using the edit function, we can construct C'n with the same `nonce + (n-1)` value, but with a known plaintext
# C'n = P'n ^ AES(nonce + (n-1), K)
#
# Let's XOR the two
# Cn ^ C'n = (Pn ^ AES(nonce + (n-1), K)) ^ (P'n ^ AES(nonce + (n-1), K)) = Pn ^ P'n
#
# We can isolate Pn...
# Pn = Cn ^ C'n ^ P'n
#
# ...and we know all part of the equation so we can recover the original plaintext !
def test():
    # Recover plaintext from challenge 7
    cipherfile = open("./set1/challenge_7.txt", "rb").read()
    plaintext = decrypt_aes128_ecb(b64decode(cipherfile), b"YELLOW SUBMARINE")

    block_size = 16
    ciphertext = encrypt_aes128_ctr(plaintext, RANDOM_KEY, RANDOM_IV)
    controlled_plaintext = b"A" * block_size
    recovered_plaintext = bytearray()

    for k in range(0, len(ciphertext), block_size):
        print(f"[x] Recovering block {k // block_size}/{len(cipherfile) // block_size}", end='\r')
        recovered_plaintext.extend(
            xor(
                xor(API_edit(ciphertext, k, b"A"*block_size)[k:k+block_size], ciphertext[k:k+16]),
                controlled_plaintext
            )
        )

    assert (recovered_plaintext.startswith(b"I\'m back and I\'m ringin\' the bell"))
    print(f"[+] Recovered plaintext:    \n{validate_pkcs7(recovered_plaintext)}")


if __name__ == "__main__":
    test()
