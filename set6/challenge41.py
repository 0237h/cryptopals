import json
from math import ceil
from time import time_ns

import sys
from os import path

sys.path.insert(0, path.abspath("set4"))

from challenge28 import sha1  # noqa # type: ignore

sys.path.insert(1, path.abspath("set5"))

from challenge39 import i2osp, invmod, os2ip  # noqa # type: ignore
from challenge40 import PQS, User  # noqa # type: ignore

# Precompute valid RSA keys for speed
USE_PRECOMPUTED_RSA_KEYS = True


class Server(User):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.hash_table = set()

    def validate(self, ciphertext: bytes) -> bytes:
        message = self.decrypt(ciphertext)

        sha_message = sha1(message)
        if sha_message in self.hash_table:
            raise ValueError(f"Message already processed: {sha_message}")

        self.hash_table.add(sha_message)
        return message


def test_server():
    server = Server("Server", e=3, pq=PQS[0] if USE_PRECOMPUTED_RSA_KEYS else None)
    message = json.dumps({
        "time": time_ns(),
        "secret": "0x53C437"
    }).encode()

    assert server.validate(server.encrypt(message)) == message
    try:
        server.validate(server.encrypt(message))
        assert False, "Should raise on same message sent more than once"
    except ValueError as e:
        assert "Message already processed" in str(e)


def test():
    server = Server("Server", e=3, pq=PQS[0] if USE_PRECOMPUTED_RSA_KEYS else None)
    alice = User("Alice", e=3, pq=PQS[1] if USE_PRECOMPUTED_RSA_KEYS else None)
    eve = User("Eve", e=3, pq=PQS[2] if USE_PRECOMPUTED_RSA_KEYS else None)

    key_size = ceil(server.key_length / 4)
    N = server.pub_key[1]
    S = 2  # Simplest value for S
    message = {
        "time": time_ns(),
        "secret": "0x53C437"
    }

    # Alice encrypts her message with server's public key
    encrypted = alice.encrypt(json.dumps(message).encode(), server.pub_key)

    # Eve intercepts C and compute C'
    altered_cipher = (
        os2ip(eve.encrypt(i2osp(S, 2), server.pub_key))  # S**E mod N
        * os2ip(encrypted)  # C
    ) % N  # C'

    # Eve gets plaintext P' from server
    altered_plaintext = server.validate(i2osp(altered_cipher, key_size))

    # Eve extracts plaintext P
    plaintext = i2osp(
        (
            os2ip(altered_plaintext)  # P'
            * invmod(S, N)  # / S
        ) % N,
        key_size
    ).lstrip(b'\x00')

    assert json.loads(plaintext) == message
    print(f"[+] Recovered plaintext: {plaintext}")


if __name__ == "__main__":
    test_server()
    test()
