import sys
from itertools import islice
from json import dumps
from os import path

sys.path.insert(0, path.abspath("set4"))

from challenge28 import sha1  # noqa # type: ignore

sys.path.insert(1, path.abspath("set5"))

from challenge39 import invmod  # noqa # type: ignore


def test():
    messages = []
    with open("./set6/challenge_44.txt") as f:
        it = iter([s[s.find(':')+2:-1] for s in f.readlines()])
        while chunk := list(islice(it, 4)):
            msg, s, r, m = chunk
            messages.append({"msg": msg, "s": s, "r": r, "m": m})

    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1  # noqa
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291  # noqa
    pub_key = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821  # noqa

    print(f"[*] Target public key: {hex(pub_key)}")
    print(f"[x] Starting search for reused k in messages...")
    while len(messages):
        pick = messages.pop()
        m1, r1, s1 = (int(pick["m"], 16), int(pick["r"]), int(pick["s"]))

        for message in messages:
            m2, s2 = (int(message["m"], 16), int(message["s"]))

            k = (((m1 - m2) % q) * invmod((s1 - s2) % q, q)) % q
            x = (invmod(r1, q)*(s1*k - m1)) % q
            y = pow(g, x, p)

            if (y == pub_key):
                key_sig = sha1(hex(x)[2:].encode()).hex()
                assert key_sig == "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
                print(f"[*] Matching messages:\n{dumps(pick, indent=4)}\n{dumps(message, indent=4)}")
                print(f"[+] Recovered private key (SHA1:{key_sig}): {hex(x)}")
                return None

    assert False, "Could not find matching messages: check file 'challenge_44.txt'"


if __name__ == "__main__":
    test()
