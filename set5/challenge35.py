from challenge33 import DH_2048_MODP
from challenge34 import MessageType, User, encrypt_payload


def test():
    alice = User("Alice")
    bob = User("Bob")
    eve = User("Eve")

    # A->M
    # Send "p", "g", "A"
    alice.init_dh()
    alice.send(eve, MessageType.CH34_DH_SETUP, (DH_2048_MODP[0], DH_2048_MODP[1], alice.public_key))

    # M->B
    # Send "p", "g*", "A"
    p, _, _ = eve.read()
    g = p - 1
    K = g if g == 1 or g == p else 1
    """
    If g = 1, Bob will generate a public key using this formula:
        B = 1^b mod p = 1
        s = B^a mod p = 1
    If g = p, Bob will generate a public key using this formula:
        B = p^b mod p = 0
        s = 0
    If g = p - 1, Bob will generate a public key using this formula:
        B = (p-1)^b mod p = sum (b k)*p^k*(-1)^(b-k) mod p = (-1)^b mod p
        s = 1 if b is even
        or s = -1 if b is odd

        We'll assume s is always positive here so s = 1
    """
    eve.send(bob, MessageType.CH34_DH_SETUP, (p, g, K))

    # B->M
    # Send "B"
    bob.read()
    bob.send(eve, MessageType.CH34_DH_SETUP, ("", "", bob.public_key))

    # M->A
    # Send "p"
    eve.read()
    eve.foreign_key = K
    eve.send(alice, MessageType.CH34_DH_SETUP, ("", "", K))

    # A->M
    # Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    alice.read()

    assert (
        alice.get_secret(alice.foreign_key)
        == eve.get_secret(eve.foreign_key)
    )

    message = b"Hello Bob !"
    alice.send(eve, MessageType.CH34_AES_MSG, encrypt_payload(alice, message))

    # M->B
    # Relay that to B (with a twist !)
    eve.relay(bob, encrypt_payload(eve, b"I hate you Bob !"))

    # B->M
    # Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    d_m, _ = bob.read()
    bob.send(eve, MessageType.CH34_AES_MSG, encrypt_payload(bob, d_m.encode()))

    # M->A
    # Relay that to A (with a twist !)
    eve.relay(alice, encrypt_payload(eve, b"I hate you too Alice !"))

    # Alice read
    alice.read()


if __name__ == "__main__":
    test()
