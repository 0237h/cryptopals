import pytest
from random import getrandbits, randbytes, randint
from typing import Callable, Generator, Optional
from challenge21 import mt19937


def random_seed_16() -> int:
    return getrandbits(16)


def mt19937_keystream(seed: int) -> Generator[int, None, None]:
    mt = mt19937(seed)
    while True:
        yield next(mt) & 0xFF


def xor_mt19937(text: bytes, seed: int) -> bytearray:
    # Clip to 16 bits seed
    seed &= 0xFFFF
    keystream = mt19937_keystream(seed)

    return bytearray([b ^ next(keystream) for b in text])


def test_mt19937_cipher():
    seed = random_seed_16()
    plaintext = b"Hello world!"
    ciphertext = xor_mt19937(plaintext, seed)

    assert (plaintext == xor_mt19937(ciphertext, seed))


def oracle_mt19937(seed: Optional[int] = None) -> Callable[[bytes], bytes]:
    if not seed:
        seed = random_seed_16()

    print(f"[*] Oracle seed: {seed}")

    def oracle(plaintext: bytes) -> bytes:
        return xor_mt19937(
            randbytes(randint(1, 16)) + plaintext,
            seed
        )

    return oracle


@pytest.mark.skip(reason="Break MT19937 stream cipher (16 bits seed recovery)")
def test():
    oracle = oracle_mt19937()
    plaintext = b"A" * 14
    ciphertext = oracle(plaintext)

    print(f"[*] Ciphertext : {ciphertext.hex()}")

    test_seed = 0
    while test_seed <= 0xFFFF and plaintext not in xor_mt19937(ciphertext, test_seed):
        print(f"[x] Testing seed: {test_seed}", end='\r')
        test_seed += 1

    if test_seed <= 0xFFFF:
        print(f"[+] Found seed for ciphertext: {test_seed}")
        print(f"[*] Plaintext: {xor_mt19937(ciphertext, test_seed)}")
    else:
        print(f"[-] Could not recover seed for ciphertext !")


if __name__ == "__main__":
    test_mt19937_cipher()
    test()
