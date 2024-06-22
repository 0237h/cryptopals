from secrets import randbelow, randbits

import sys
from os import path
from typing import Callable

sys.path.insert(1, path.abspath("set4"))  # Python hack to resolve set1/ challenges imports

from challenge28 import sha1  # noqa # type: ignore

MAX_PRIVATE_KEY_SIZE_BITS = 2048
# From https://datatracker.ietf.org/doc/html/rfc3526#section-3
DH_2048_MODP = (
    int.from_bytes(
        bytes.fromhex(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1"
            "29024e088a67cc74020bbea63b139b22514a08798e3404dd"
            "ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245"
            "e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
            "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d"
            "c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f"
            "83655d23dca3ad961c62f356208552bb9ed529077096966d"
            "670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
            "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9"
            "de2bcbf6955817183995497cea956ae515d2261898fa0510"
            "15728e5a8aacaa68ffffffffffffffff"
        )
    ),
    2
)


def dh(p: int, g: int):
    priv_k = randbits(randbelow(MAX_PRIVATE_KEY_SIZE_BITS))
    pub_k = pow(g, priv_k, p)

    def _secret(other_pub_k: int) -> int:
        return abs(pow(other_pub_k, priv_k, p))

    def _enc_keys(other_pub_k: int) -> tuple[bytes, bytes]:
        '''Return two 128-bits keys for encryption and MAC derived from the DH secret using SHA-1'''
        secret = _secret(other_pub_k).to_bytes(p.bit_length() * 8)
        enc_key = sha1(secret)[:16]  # Truncate to 128 bits
        mac_key = sha1(secret[:len(secret) // 2])[:16]  # Use different value than previous

        return (enc_key, mac_key)

    return (priv_k, pub_k, _secret, _enc_keys)


def test():
    alice_pk, alice_pubkey, alice_get_secret, alice_get_enc_keys = dh(*DH_2048_MODP)
    bob_pk, bob_pubkey, bob_get_secret, _ = dh(*DH_2048_MODP)

    big_int_to_hex: Callable[[int], str] = lambda x: x.to_bytes(MAX_PRIVATE_KEY_SIZE_BITS // 8).hex()
    print(f"[*] [Alice] Private key: {big_int_to_hex(alice_pk)}")
    print(f"[*] [Alice] Public key: {big_int_to_hex(alice_pubkey)}")
    print(f"[*] [Bob] Private key: {big_int_to_hex(bob_pk)}")
    print(f"[*] [Bob] Public key: {big_int_to_hex(bob_pubkey)}")

    assert alice_get_secret(bob_pubkey) == bob_get_secret(alice_pubkey)
    print(f"[*] Shared secret: {big_int_to_hex(alice_get_secret(bob_pubkey))}")

    enc_key, mac_key = alice_get_enc_keys(bob_pubkey)
    print(f"[*] Encryption key: {enc_key.hex()}")
    print(f"[*] MAC key: {mac_key.hex()}")


if __name__ == "__main__":
    test()
