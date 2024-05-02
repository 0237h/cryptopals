import pytest
from base64 import b64decode
from secrets import token_bytes, randbelow
from string import printable

from challenge11 import detect_aes_mode, random_128

import sys
from os import path


sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge7 import encrypt_aes128_ecb  # noqa # type: ignore
from challenge8 import find_patterns  # noqa # type: ignore


# SIMPLE
# ------
# For the simple version in challenge 12, there is no prefix hence we can control directly where the bytes of the secret
# will be in order to extract them one by one (by generating a list of single byte possibilities for a block).
#
# aaaaaaaaaaaaaaaSECRET
# ---------------|---------------|
#
# Then generate [oracle(aaaaaaaaaaaaaaaA), oracle(aaaaaaaaaaaaaaaB), etc.] and compare the results.
#
# HARDER
# ------
# Here, a random count of random bytes is prepended EVERYTIME the oracle is called. We cannot determine in advance a
# fixed length for the prefix so we have to rely on other means to control where the byte of the secrets will be.
#
# [random]AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[SECRET][SECRET][SECRET][SECRET][SECRET]
# ---------------|---------------|---------------|---------------|---------------|---------------|
#
# Initially, by passing a plaintext of THREE block length, we can control where the secret bytes will start by
# determining the indexes of the repeated blocks (a flaw of ECB).
#
# Now if the secret is longer than a block, the following blocks will also contain secret characters we want to recover
# (and only those, no plaintext added).
#
# Code below is pretty horrible, doesn't extract the text fully (works for about 3/4 of the message) but that's enough
# for me :)


MAX_TRIES_BEFORE_RETURN = 1_000


def get_ecb_oracle_harder():
    key = random_128()

    def _ecb_oracle(plaintext: bytes) -> bytes:
        # Add random count (up to 63) of random bytes on EVERY oracle call (as in "every plaintext" in the challenge)
        # This makes it way harder than it needs to be :')
        random_bytes = token_bytes(randbelow(64))

        return encrypt_aes128_ecb(
            random_bytes +
            plaintext +
            b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                      "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                      "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
                      ),
            key
        )

    return _ecb_oracle


def index_of_first_repeated_block(ciphertext: bytes) -> int:
    ciphertext_hex = ciphertext.hex()
    patterns = find_patterns(ciphertext_hex, 32)

    if (patterns):
        return ciphertext_hex.index(patterns[0][0]) // 32
    else:
        return -1


def count_repeated_blocks(ciphertext: bytes) -> int:
    patterns = find_patterns(ciphertext.hex(), 32)

    if (patterns):
        return patterns[0][1]
    else:
        return -1


@pytest.mark.skip(reason="Byte-at-a-time ECB decryption (harder)")
def test():
    oracle = get_ecb_oracle_harder()

    block_size = 16
    detected_mode = detect_aes_mode(oracle(b'A' * (block_size * block_size)))
    print(f"[+] Detected cipher mode : {detected_mode}")

    plain_secret = bytearray()
    secret_block = 0  # Used for offsetting inputs
    possible_byte_values = [x.encode() for x in printable]  # Optimized for this challenge to speed up recovery

    for _ in range(100):
        # For recovering last byte of secret blocks, we bruteforce all possible byte values and run the oracle until
        # the byte count alines all the blocks (multiple of block_size)
        if (len(plain_secret) + 1) % 16 == 0:
            for x in possible_byte_values:
                for _ in range(80):
                    crafted = b''
                    if secret_block > 0:
                        # Input is different for subsequent secret blocks, a running theme in the following algorithms
                        # and a major source of headaches... Basically trying to have a running window of the recovered
                        # secret spanning one block - 1 byte
                        crafted = (plain_secret[block_size * (secret_block - 1) +
                                   len(plain_secret) % block_size + 1:] + x) * 3  # Repetition of input, also critical
                    else:
                        crafted = b'\x01' * block_size + (plain_secret + x) * 3

                    # When 4 repeated blocks appears (3 from input + target secret block) we found the last byte
                    if count_repeated_blocks(oracle(crafted)) == 4:
                        plain_secret += x
                        print(f"[*] {plain_secret}", end='\r')
                        break

        if len(plain_secret) > 0 and len(plain_secret) % block_size == 0:
            secret_block += 1

        # Here the standard algorithm from Challenge 12 applies where we craft all possible values for the last byte of
        # the target block
        possible_outputs = {}
        for x in possible_byte_values:
            crafted = b''
            # For the first secret block we pad with b'\x01' but for subsequent one, we use a running window of the
            # recovered secret
            if secret_block > 0:
                crafted = (plain_secret[block_size * (secret_block - 1) + len(plain_secret) % block_size + 1:] + x) * 3
            else:
                crafted = (
                    b'\x01' * (block_size - len(plain_secret) - 1) +
                    plain_secret + x
                ) * 3

            ciphertext = b''
            # Make sure the possible byte values are at last byte position in block (repeated input appears 3 times)
            while count_repeated_blocks(ciphertext) < 3:
                ciphertext = oracle(crafted)

            i = index_of_first_repeated_block(ciphertext)
            # Take the first repeated one, doesn't matter they're all equal
            key = ciphertext[i*block_size:(i+1)*block_size].hex()
            possible_outputs[key] = x

        tries = 0  # Supposed to detect when no bytes from the secret are left to decode, dubious
        while tries < MAX_TRIES_BEFORE_RETURN:
            ciphertext = b''
            if secret_block > 0:
                ciphertext = oracle(plain_secret[block_size * (secret_block - 1) + len(plain_secret) % block_size:] * 3)
            else:
                ciphertext = oracle(b'\x01' * block_size * 3)

            i = index_of_first_repeated_block(ciphertext)

            # We cut the target block and place it next to our input otherwise the random count of bytes will kill us
            # (no better explanation than that sorry)
            if secret_block > 0:
                ciphertext = ciphertext[:(i+2)*block_size] + \
                    ciphertext[(i+2+secret_block) * block_size:(i+3+secret_block)*block_size]

            # Hence, only look up the block two positions up from the first repeated block
            recovered_byte = possible_outputs.get(
                ciphertext[(i+2)*block_size:(i+3)*block_size].hex()
            )

            if (recovered_byte):
                plain_secret += recovered_byte
                break

            tries += 1

        if tries == MAX_TRIES_BEFORE_RETURN:
            break

        print(f"[*] {plain_secret}", end='\r')

    print('')
    print(f"[+] Recovered secret (len={len(plain_secret)})")
    print(f"{plain_secret}")


if __name__ == "__main__":
    test()
