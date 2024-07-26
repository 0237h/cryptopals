import sys
from os import path

from challenge43 import dsa_sha1

sys.path.insert(1, path.abspath("set5"))

from challenge39 import invmod  # noqa # type: ignore


def test():
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1  # noqa
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    # g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291  # noqa

    m1, m2 = (b"Hello, world", b"Goodbye, world")

    print(f"[*] --- g = 0 ---")
    g = 0
    _, pub_key, _, sign, verify = dsa_sha1((p, q, g))

    r, s = sign(m1, bypass_safety_check=True)
    print(f"[*] Signing '{m1.decode()}': {(hex(r), hex(s))}")

    assert verify(m1, r, s, bypass_safety_check=True)
    print(f"[+] Verified '{m1.decode()}' with {(hex(r), hex(s))}")
    assert verify(m1, r, 0xDEADBEEF, bypass_safety_check=True)
    print(f"[!] Also verified '{m1.decode()}' with {(hex(r), hex(0xDEADBEEF))}")

    print(f"[*] --- g = p + 1 ---")
    g = p + 1
    _, pub_key, _, sign, verify = dsa_sha1((p, q, g))

    r1, s1 = sign(m1, bypass_safety_check=True)
    print(f"[*] Signing '{m1.decode()}': {(hex(r1), hex(s1))}")
    assert verify(m1, r1, s1, bypass_safety_check=True)
    print(f"[+] Verified '{m1.decode()}' with {(hex(r1), hex(s1))}")

    r2, s2 = sign(m2, bypass_safety_check=True)
    print(f"[*] Signing '{m2.decode()}': {(hex(r2), hex(s2))}")
    assert verify(m2, r2, s2, bypass_safety_check=True)
    print(f"[+] Verified '{m2.decode()}' with {(hex(r2), hex(s2))}")

    z = 0xDEADBEEF
    r = pow(pub_key, z, p) % q
    s = (r*invmod(z, q)) % q

    print(f"[*] Created magic signature pair from z={hex(z)}: {(hex(r), hex(s))}")
    assert verify(m1, r, s, bypass_safety_check=True)
    print(f"[!] Also verified '{m1.decode()}' with {(hex(r), hex(s))}")
    assert verify(m2, r, s, bypass_safety_check=True)
    print(f"[!] Also verified '{m2.decode()}' with {(hex(r), hex(s))}")


if __name__ == "__main__":
    test()
