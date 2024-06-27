from random import choice
from challenge34 import MessageType
from challenge36 import User, int_to_bytes, sha1_hash

import sys
from os import path

sys.path.insert(1, path.abspath("set4"))  # Python hack to resolve set4/ challenges imports

from challenge31 import hmac_sha1  # noqa # type: ignore

sys.path.insert(1, path.abspath("set2"))

from challenge11 import random_128  # noqa # type: ignore

# From https://en.wikipedia.org/wiki/Wikipedia:10,000_most_common_passwords#Top_100
COMMON_100_PASSWORDS = [
    b"123456",
    b"password",
    b"12345678",
    b"qwerty",
    b"123456789",
    b"12345",
    b"1234",
    b"111111",
    b"1234567",
    b"dragon",
    b"123123",
    b"baseball",
    b"abc123",
    b"football",
    b"monkey",
    b"letmein",
    b"696969",
    b"shadow",
    b"master",
    b"666666",
    b"qwertyuiop",
    b"123321",
    b"mustang",
    b"1234567890",
    b"michael",
    b"654321",
    b"pussy",
    b"superman",
    b"1qaz2wsx",
    b"7777777",
    b"fuckyou",
    b"121212",
    b"000000",
    b"qazwsx",
    b"123qwe",
    b"killer",
    b"trustno1",
    b"jordan",
    b"jennifer",
    b"zxcvbnm",
    b"asdfgh",
    b"hunter",
    b"buster",
    b"soccer",
    b"harley",
    b"batman",
    b"andrew",
    b"tigger",
    b"sunshine",
    b"iloveyou",
    b"fuckme",
    b"2000",
    b"charlie",
    b"robert",
    b"thomas",
    b"hockey",
    b"ranger",
    b"daniel",
    b"starwars",
    b"klaster",
    b"112233",
    b"george",
    b"asshole",
    b"computer",
    b"michelle",
    b"jessica",
    b"pepper",
    b"1111",
    b"zxcvbn",
    b"555555",
    b"11111111",
    b"131313",
    b"freedom",
    b"777777",
    b"pass",
    b"fuck",
    b"maggie",
    b"159753",
    b"aaaaaa",
    b"ginger",
    b"princess",
    b"joshua",
    b"cheese",
    b"amanda",
    b"summer",
    b"love",
    b"ashley",
    b"6969",
    b"nicole",
    b"chelsea",
    b"biteme",
    b"matthew",
    b"access",
    b"yankees",
    b"987654321",
    b"dallas",
    b"austin",
    b"thunder",
    b"taylor",
    b"matrix"
]
LINE_CLEAR = "\x1b[2K"


def test_protocol():
    carol = User("Carol")
    steve = User("Steve")

    email = b"carol@domain.xyz"
    p = choice(COMMON_100_PASSWORDS)

    # S
    # x = SHA256(salt|password)
    # v = g**x % n
    steve.init_srp(email, p)

    # C->S
    # I, A = g**a % n
    carol.init_dh()
    carol.send(steve, MessageType.CH35_SRP_SETUP, (None, carol.public_key, None))

    # S->C
    # Send salt, B=g**b % N
    # salt, B = g**b % n, u = 128 bit random number
    steve.read()
    steve.send(carol, MessageType.CH35_SRP_SETUP, (steve.salt, steve.public_key, None))
    carol.read()

    # C
    # x = SHA256(salt|password)
    # S = B**(a + ux) % n
    # K = SHA256(S)
    #
    # S
    # S = (A * v ** u)**b % n
    # K = SHA256(S)
    assert carol.compute_k(email, p, simplified=True) == steve.compute_k(email, p)

    # C->S
    # Send HMAC-SHA256(K, salt)
    hmac_carol = hmac_sha1(carol.K, carol.salt)
    carol.send(steve, MessageType.CH35_SRP_HMAC, (hmac_carol,))

    # S->C
    # Send "OK" if HMAC-SHA256(K, salt) validates
    _, is_valid = steve.read()
    assert is_valid

    print('='*20)


def test():
    carol = User("Carol")
    eve = User("Eve")
    steve = User("Steve")

    email = b""
    p = choice(COMMON_100_PASSWORDS)
    u = int.from_bytes(random_128())

    steve.init_srp(email, p)

    carol.init_dh()
    carol.send(eve, MessageType.CH35_SRP_SETUP, (None, carol.public_key, u))

    eve.init_dh()
    eve.public_key = carol.public_key
    eve.relay(steve, (None, eve.public_key, 1))  # Set u = 1

    steve.read()
    steve.send(eve, MessageType.CH35_SRP_SETUP, (steve.salt, steve.public_key, u))
    eve.relay(carol, (b'', eve.g, 1))  # Set salt to empty value, B = g
    eve.u = 1
    carol.read()

    carol.compute_k(email, p, simplified=True)

    target_hmac = hmac_sha1(carol.K, carol.salt)
    print(f"[*] Target HMAC: {target_hmac.hex()}")

    guess = b''
    for guess in COMMON_100_PASSWORDS:
        guess_hmac = hmac_sha1(
            int_to_bytes(
                sha1_hash(eve.public_key * pow(eve.g, sha1_hash(guess), eve.N) % eve.N)
            ),
            b''
        )
        print(f"{LINE_CLEAR}[x] Trying password {guess} (HMAC: {guess_hmac.hex()})", end='\r')

        if guess_hmac == target_hmac:
            print(f"\n[+] Found password: {guess.decode()}")
            break


if __name__ == "__main__":
    test_protocol()
    test()
