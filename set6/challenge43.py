import sys
from math import ceil, gcd
from os import path
from secrets import randbelow, randbits
from typing import Optional

sys.path.insert(0, path.abspath("set4"))

from challenge28 import sha1  # noqa # type: ignore

sys.path.insert(1, path.abspath("set5"))

from challenge39 import i2osp, invmod, is_probably_prime, os2ip  # noqa # type: ignore


def secrets_randint(a_inclusive: int, b_inclusive: int) -> int:
    """
    Replicate the behavior of `random.randint` using `secrets.randbelow`.
    Returns an integer in the [a, b] range. Asserts that a <= b.
    """
    assert b_inclusive >= a_inclusive, "a cannot be greater than b for range ([a, b])"
    return randbelow(b_inclusive - a_inclusive + 1) + a_inclusive


def dsa_sha1(pqg: Optional[tuple[int, int, int]] = None, xy: Optional[tuple[int, int]] = None):
    """Adapted from https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Operation"""
    # From FIPS 186-4, choose 160 bits for SHA-1
    L, N = (1024, 160)

    if pqg:
        p, q, g = pqg
    else:
        def _dsa_sha1_generate_pq() -> tuple[int, int]:
            """Adapted from FIPS 186-4 Appendix A.1.1.2"""
            outlen = N
            seedlen = N
            seedlen_bytes = seedlen // 8

            n = ceil(L/outlen) - 1
            b = L - 1 - n*outlen

            while True:
                domain_parameter_seed = randbits(seedlen)
                U = os2ip(sha1(i2osp(domain_parameter_seed, seedlen_bytes))) % pow(2, N-1)
                q = pow(2, N-1) + U + 1 - (U % 2)

                if not is_probably_prime(q):
                    continue

                offset = 1
                for _ in range(4*L):
                    V = []
                    for j in range(n+1):
                        temp = (domain_parameter_seed + offset + j) % pow(2, seedlen)
                        V.append(os2ip(sha1(i2osp(temp, ceil(temp.bit_length() / 8)))))

                    W = sum([v * pow(2, i*outlen) for (i, v) in enumerate(V[:-1])]) + \
                        (V[-1] % pow(2, b)) * pow(2, n * outlen)
                    X = W + pow(2, L-1)
                    c = X % (2*q)
                    p = X - (c - 1)

                    if p >= pow(2, L-1) and is_probably_prime(p):
                        return (p, q)

                    offset += 1

        p, q = _dsa_sha1_generate_pq()
        assert gcd(p-1, q) != 1, "Invalid (p, q) pair: p - 1 not a multiple of q"
        while True:
            h = secrets_randint(2, p-2)
            g = pow(h, (p-1)//q, p)

            if g != 1:
                break

    if xy:
        private_key, public_key = xy
    else:
        private_key = secrets_randint(1, q-1)
        public_key = pow(g, private_key, p)

    def _dsa_sha1_sign(message: bytes, k: Optional[int] = None) -> tuple[int, int]:
        """Adapted from https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#3._Signing"""
        while True:
            k = secrets_randint(1, q-1) if k is None else k
            r = pow(g, k, p) % q
            s = (invmod(k, q)*(os2ip(sha1(message)) + private_key*r)) % q

            if r != 0 and s != 0:
                return (r, s)

    def _dsa_sha1_verify(message: bytes, r: int, s: int, public_key: int = public_key) -> bool:
        """Adapted from https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#4._Signature_Verification"""
        assert r > 0 and r < q and s > 0 and s < q, "Invalid signature"

        w = invmod(s, q)
        u1 = (os2ip(sha1(message)) * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(public_key, u2, p)) % p) % q

        return v == r

    return (
        L,
        public_key,
        private_key,
        _dsa_sha1_sign,
        _dsa_sha1_verify
    )


def test_secrets_randint():
    valid_test_ranges = [
        (0, 0),
        (1, 1),
        (0, 10),
        (10, 20),
        (20, 20)
    ]

    try:
        secrets_randint(1, 0)
    except AssertionError as e:
        assert "a cannot be greater than b for range ([a, b])" in str(e)

    for (a, b) in valid_test_ranges:
        for _ in range(b-a+1):  # Sample n = b-a values
            x = secrets_randint(a, b)
            assert a <= x and x <= b


def test_dsa_sha1():
    # Test vectors from https://datatracker.ietf.org/doc/html/rfc6979#autoid-32
    _, _, _, sign, verify = dsa_sha1(
        (
            0x86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779,  # noqa
            0x996F967F6C8E388D9E28D01E205FBA957A5698B1,
            0x07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA417BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD  # noqa
        ),
        (
            0x411602CB19A6CCC34494D79D98EF1E7ED5AF25F7,
            0x5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F65392195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E682F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B  # noqa
        )
    )

    message = b"sample"
    r, s = sign(message, 0x7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5B)

    assert r == 0x2E1A0C2562B2912CAAF89186FB0F42001585DA55 and s == 0x29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5
    assert verify(message, r, s)

    print(f"[*] --- Testing DSA ---")
    print(f"[x] Generating DSA keys...")
    key_length, pub_key, priv_key, sign, verify = dsa_sha1()

    print(f"[*] Key length: {key_length} bits")
    print(f"[*] Public key: {pub_key}")
    print(f"[*] Private key: {priv_key}")

    message = b"sample"
    r, s = sign(message)
    print(f"[*] Message: {message}")
    print(f"[*] Signature: {(hex(r), hex(s))}")

    assert verify(message, r, s)
    print(f"[+] Signature OK !")
    print(f"[*] --- End testing DSA ---")


def test():
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1  # noqa
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291  # noqa
    pub_key = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17  # noqa
    message = b'''For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
'''
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940

    # Precompute constants for speed-up
    v1 = invmod(r, q)
    v2 = int(sha1(message).hex(), 16)

    def _recover_privatekey_from_k(k):
        #     (s * k) - H(msg)
        # x = ----------------  mod q
        #             r
        return (v1*(s*k - v2)) % q

    print(f"[*] --- Recovering private key from known message k ---")
    x = y = 0
    for k in range(0xFFFF + 1):
        print(f"[x] Guessing k={k}", end='\r')
        x = _recover_privatekey_from_k(k)
        y = pow(g, x, p)

        if y == pub_key:
            break

    print()
    if y == pub_key:
        key_sig = sha1(hex(x)[2:].encode()).hex()
        assert key_sig == "0954edd5e0afe5542a4adf012611a91912a3ec16"
        print(f"[+] Recovered private key (SHA1:{key_sig}): {hex(x)}")
    else:
        print(f"[-] Failed to recover private key !")


if __name__ == "__main__":
    test_secrets_randint()
    test_dsa_sha1()
    test()
