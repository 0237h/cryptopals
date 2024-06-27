from challenge34 import MessageType
from challenge36 import User

import sys
from os import path

sys.path.insert(1, path.abspath("set4"))  # Python hack to resolve set4/ challenges imports

from challenge28 import sha1  # noqa # type: ignore
from challenge31 import hmac_sha1  # noqa # type: ignore


def test():
    carol = User("Carol")
    steve = User("Steve")

    email = b"carol@domain.xyz"
    p = b"passw0rd"

    # S
    # Generate salt as random integer
    # Generate string xH=SHA256(salt|password)
    # Convert xH to integer x somehow (put 0x on hexdigest)
    # Generate v=g**x % N
    # Save everything but x, xH
    steve.init_srp(email, p)

    # C->S
    # Send I, A=g**a % N (a la Diffie Hellman)
    carol.init_dh()
    carol.send(steve, MessageType.CH35_SRP_SETUP, (None, 0, None))  # Login without password with A = 0 or multiple of N

    # S->C
    # Send salt, B=kv + g**b % N
    # Compute string uH = SHA256(A|B), u = integer of uH
    steve.public_key = (steve.public_key + (steve.k * steve.v)) % steve.N  # B=kv + g**b % N
    steve.read()
    steve.send(carol, MessageType.CH35_SRP_SETUP, (steve.salt, steve.public_key, None))
    carol.read()

    # C, S
    # For Steve, S = (A*v^u)^b = 0
    # Generate K = SHA256(S) = known
    carol.K = int(sha1(b"\x00").hex(), 16).to_bytes(20, "little")
    assert carol.K == steve.compute_k(email, p)

    # C->S
    # Send HMAC-SHA256(K, salt)
    hmac_carol = hmac_sha1(carol.K, carol.salt)
    carol.send(steve, MessageType.CH35_SRP_HMAC, (hmac_carol,))

    # S->C
    # Send "OK" if HMAC-SHA256(K, salt) validates
    hmac_steve, is_valid = steve.read()

    if is_valid:
        print(f"[+] HMAC is valid: {hmac_steve.hex()}")
    else:
        print(f"[-] HMAC invalid:\nCarol = {hmac_carol.hex()}\nSteve = {hmac_steve.hex()}")


if __name__ == "__main__":
    test()
