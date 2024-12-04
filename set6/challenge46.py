import pytest
import sys
from base64 import b64decode
from math import log2
from os import path, system
from sys import platform
from typing import Literal

sys.path.insert(1, path.abspath("set5"))

from challenge39 import i2osp, os2ip, rsa  # noqa # type: ignore
from challenge40 import PQS  # noqa # type: ignore


# Precompute valid RSA keys for speed
USE_PRECOMPUTED_RSA_KEYS = True

if USE_PRECOMPUTED_RSA_KEYS:
    print(f"[!] Using precomputed RSA keys for speed")


def get_oracle():
    print(f"[x] Generating oracle keys...")
    key_length, pub_key, _, enc, dec = rsa(pq=PQS[0] if USE_PRECOMPUTED_RSA_KEYS else None)

    def _f(ciphertext: bytes) -> Literal["even"] | Literal["odd"]:
        return "odd" if os2ip(dec(ciphertext, use_padding=False, strip_null_bytes=False)) & 1 else "even"

    return (key_length // 4, pub_key, enc, dec, _f)


def test_oracle():
    _, _, enc, _, oracle = get_oracle()

    odd = b"\xff"
    even = b"\xfe"

    assert oracle(enc(odd)) == "odd"
    assert oracle(enc(even)) == "even"


@pytest.mark.skip(reason="RSA parity oracle")
def test():
    key_length_bytes, pub_key, enc, _, oracle = get_oracle()
    plaintext = b64decode(
        "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    )
    ciphertext = enc(plaintext, use_padding=False)
    c = os2ip(ciphertext)

    e, n = pub_key
    bound = (0, n)
    max_iterations = int(log2(n).real) + 1

    for i in range(max_iterations):
        system('cls' if platform == 'win32' else 'clear')
        print(f"[x] Progress ({i+1}/{max_iterations}): {bound}")

        c = (pow(2, e) * c) % n
        delta = bound[1] - bound[0]  # Avoid loss of precision due to large numbers
        if oracle(i2osp(c, key_length_bytes)) == "even":
            bound = (bound[0], bound[1] - delta//2)
        else:
            bound = (bound[0] + delta//2, bound[1])

    recovered = i2osp(bound[1], key_length_bytes).strip(b'\x00')
    print(f'[+] Recovered: {recovered.decode()}')
    assert recovered == plaintext


if __name__ == "__main__":
    test_oracle()
    test()
