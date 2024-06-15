import pytest
from secrets import token_bytes, randbelow
from time import perf_counter_ns, sleep
from typing import Callable, Concatenate

from challenge28 import BLOCK_SIZE_BYTES, sha1

import sys
from os import path
from typing import Literal

sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge2 import xor  # noqa # type: ignore

RANDOM_KEY = token_bytes(randbelow(128))
SLEEP_TIME_MS = 50


def _computeBlockSizedKey(key: bytes, f_hash: Callable[Concatenate[bytes, ...], bytes], blockSize: int):
    '''Adapted from Wikipedia pseudocode: https://en.wikipedia.org/wiki/HMAC'''
    # Keys longer than blockSize are shortened by hashing them
    if (len(key) > blockSize):
        key = f_hash(key)

    # Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if (len(key) < blockSize):
        key += b'\x00'*(blockSize - len(key))

    assert len(key) == blockSize, f"Key length ({len(key)}) is not equal to blockSize ({blockSize})"
    return key


def hmac(key: bytes, message: bytes, f_hash: Callable[Concatenate[bytes, ...], bytes], blockSize: int) -> bytes:
    '''Adapted from Wikipedia pseudocode: https://en.wikipedia.org/wiki/HMAC'''
    block_sized_key = _computeBlockSizedKey(key, f_hash, blockSize)

    o_key_pad = xor(block_sized_key, b'\x5c' * blockSize)
    i_key_pad = xor(block_sized_key, b'\x36' * blockSize)

    return f_hash(o_key_pad + f_hash(i_key_pad + message))


def hmac_sha1(key: bytes, message: bytes) -> bytes:
    return hmac(key, message, sha1, BLOCK_SIZE_BYTES)


def test_hmac():
    assert (
        hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog").hex()
        == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
    )


def insecure_compare(a: bytes, b: bytes) -> bool:
    if len(b) < len(a):
        return insecure_compare(b, a)

    i = 0
    while (i < len(a)):
        if (a[i] != b[i]):
            break
        i += 1
        sleep(SLEEP_TIME_MS / 1000)

    return i == len(b)


def app(file: str, signature: str, secure: bool = False) -> int:
    hmac = hmac_sha1(RANDOM_KEY, file.encode())

    if secure:
        return 200 if hmac.hex() == signature else 500
    else:
        return 200 if insecure_compare(hmac, bytes.fromhex(signature)) else 500


def test_app():
    file = "foo"
    signature = hmac_sha1(RANDOM_KEY, file.encode())

    assert app(file, signature.hex(), True) == 200
    assert app(file, signature.hex(), False) == 200
    assert app(file, (signature[:-1] + b'\x00').hex(), True) == 500
    assert app(file, (signature[:-1] + b'\x00').hex(), False) == 500


def break_app_hmac(app_compare_resolution_ns: int, averaging_count: int = 10) -> tuple[str, str]:
    def _time_app(sig: str, averaging_count: int) -> tuple[int, int]:
        app_result = 500
        # Adding average reduce chances of getting a wrong byte as a fluke
        average = 0

        for _ in range(averaging_count):
            start = perf_counter_ns()
            app_result = app(file, sig)
            end = perf_counter_ns()

            average += end - start

        return (app_result, average // averaging_count)

    file = "myfile"
    target_signature = hmac_sha1(RANDOM_KEY, file.encode())
    print(f"[*] Random key is {RANDOM_KEY.hex()}")
    print(f"[*] Target signature is {target_signature.hex()}")

    # Start with random bytes (SHA-1 output is 20 bytes)
    test_signature = bytearray(token_bytes(20))
    target_byte = 0
    # Resolution for comparing two calls to `app` in nanoseconds
    app_result, previous_timing = _time_app(test_signature.hex(), averaging_count)

    while (app_result == 500 and target_byte < len(test_signature)):
        app_result, timing = _time_app(test_signature.hex(), averaging_count)
        print(f"[x] Recovering byte {target_byte + 1}/{len(test_signature)}: {test_signature.hex()}", end='\r')

        # Adding the resolution to our previous timing and comparing with the current one ensures we have successfully
        # checked one more valid byte than the previous run
        if (timing > previous_timing + app_compare_resolution_ns):
            previous_timing = timing
            target_byte += 1
        else:
            test_signature[target_byte] = (test_signature[target_byte] + 1) % 0xFF

    print()
    if (app_result != 200):
        print(f"[-] Failed to recover HMAC for file '{file}'")
        return (file, "unknown")
    else:
        assert target_signature == test_signature
        print(f"[+] Recovered HMAC for file '{file}': {test_signature.hex()}")
        return (file, test_signature.hex())


@pytest.mark.skip(reason="Break HMAC-SHA1 with an artificial timing leak (50 ms)")
def test():
    # App has 50ms timing leak, resolution here is set for 10ms difference
    break_app_hmac(app_compare_resolution_ns=10 * 10**6, averaging_count=1)


if __name__ == "__main__":
    test_hmac()
    test_app()
    test()
