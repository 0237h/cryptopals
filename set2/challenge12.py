from typing import Callable
import pytest
from string import printable
from base64 import b64decode
from challenge11 import detect_aes_mode, random_128

import sys
from os import path

sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge7 import encrypt_aes128_ecb  # noqa # type: ignore


def detect_cipher_block_size(oracle: Callable[[bytes], bytes]) -> int:
    k = 1
    detected_block_size = len(oracle(b'A'))
    while True:
        cipher_size = len(oracle(b'A' * k))
        if detected_block_size != cipher_size:
            detected_block_size = cipher_size - detected_block_size
            break
        k += 1

    return detected_block_size


def get_ecb_oracle():
    key = random_128()

    def _ecb_oracle(plaintext: bytes) -> bytes:
        return encrypt_aes128_ecb(
            plaintext + b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
                                  "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
                                  "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"),
            key
        )

    return _ecb_oracle


@pytest.mark.skip(reason="Byte-at-a-time ECB decryption (simple)")
def test():
    oracle = get_ecb_oracle()

    detected_block_size = detect_cipher_block_size(oracle)
    print(f"[+] Detected cipher block size : {detected_block_size} bytes")

    detected_mode = detect_aes_mode(oracle(b'A' * (detected_block_size * detected_block_size)))
    print(f"[+] Detected cipher mode : {detected_mode}")

    secret_len_bytes = len(oracle(b''))
    plain_secret = bytearray()
    # possible_byte_values = [x.to_bytes() for x in range(256)]
    possible_byte_values = [x.encode() for x in printable]  # Optimized for this challenge to speed up recovery

    print(f"[x] Recovering possibly {secret_len_bytes} bytes of secret...")
    for k in range(0, secret_len_bytes, detected_block_size):
        for i in range(1, detected_block_size + 1):
            crafted = b'A' * (detected_block_size - i)

            possible_outputs = {
                oracle(crafted + plain_secret + x)[k:k+detected_block_size].hex(): x
                for x in possible_byte_values
            }

            try:
                plain_secret += possible_outputs[oracle(crafted)[k:k+detected_block_size].hex()]
            except KeyError:
                break  # We have reached end of secret length

            print(f"[*] {len(plain_secret)}/{secret_len_bytes} bytes", end='\r')

    assert (
        plain_secret.hex() == "526f6c6c696e2720696e206d7920352e300a57697468206d79207261672d746f7020646f776e20736f206d" +
        "7920686169722063616e20626c6f770a546865206769726c696573206f6e207374616e64627920776176696e67206a75737420746f20" +
        "7361792068690a44696420796f752073746f703f204e6f2c2049206a7573742064726f76652062790a"
    )

    print(f"[*] Recovered secret ({len(plain_secret)} bytes) :")
    print(plain_secret.decode())


if __name__ == "__main__":
    test()
