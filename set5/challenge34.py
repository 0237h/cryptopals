from dataclasses import astuple, dataclass
from enum import Enum, auto
from random import randbytes
from typing import Optional, Self

from challenge33 import DH_2048_MODP, dh

import sys
from os import path

sys.path.insert(1, path.abspath("set2"))  # Python hack to resolve set2/ challenges imports

from challenge10 import encrypt_aes128_cbc, decrypt_aes128_cbc  # noqa # type: ignore


class MessageType(Enum):
    CH34_DH_SETUP = auto()
    CH34_AES_MSG = auto()


@dataclass
class Message:
    sender: str
    message_type: MessageType
    message_payload: tuple

    def __iter__(self):
        return iter(astuple(self))

    def __getitem__(self, keys):
        return iter(getattr(self, k) for k in keys)


class User:
    """
    Mockup for a protocol using lists as message queues for user to read / write to.
    """

    def __init__(self, name: str) -> None:
        self.message_queue: list[Message] = []
        self.name = name

    def init_dh(self, dh_params: tuple[int, int] = DH_2048_MODP) -> None:
        self.private_key, self.public_key, self.get_secret, self.get_enc_keys = dh(*dh_params)

    def send(self, user: Self, message_type: MessageType, message_payload: tuple) -> None:
        user.message_queue.append(Message(self.name, message_type, message_payload))

    def read(self) -> tuple:
        try:
            message = self.message_queue.pop()
            print(f"[*] [{self.name}] Received from {message.sender}")

            return self._parse(message)
        except IndexError:
            print(f"[!] [{self.name}] No messages left in queue")
            return ()

    def relay(self, user: Self, alter_payload: Optional[tuple] = None) -> None:
        _, message_type, message_payload = self.message_queue[-1]
        self.send(user, message_type, alter_payload if alter_payload else message_payload)
        self.read()

    def _parse(self, message: Message) -> tuple:
        sender, message_type, message_payload = message
        match message_type:
            case MessageType.CH34_DH_SETUP:
                assert len(message_payload) >= 2, \
                    f"[-] Could not parse message (type={message_type}) from {sender}: wrong_payload\n{message_payload}"

                p, g, X = message_payload

                if p and g:
                    self.init_dh((int(p), int(g)))

                if X:
                    self.foreign_key = int(X)

                print(f"[*] [{self.name}] Received DH params: {(p, g, X)}")
                return (p, g, X)
            case MessageType.CH34_AES_MSG:
                assert len(message_payload) == 2, \
                    f"[-] Could not parse message (type={message_type}) from {sender}: wrong_payload\n{message_payload}"

                m, iv = message_payload

                if m and iv:
                    print(f"[*] [{self.name}] Received encrypted message: {m}")
                    d_m = decrypt_aes128_cbc(
                        bytes.fromhex(m),
                        self.get_enc_keys(self.foreign_key)[0],
                        bytes.fromhex(iv)
                    )
                    print(f"[+] [{self.name}] Decrypted message: {d_m}")

                    return (d_m.decode(), iv)
                else:
                    return (m, iv)
            case _:
                print(f"[!] [{self.name}] Unrecognized message type: {message_type}")
                return ()


def test_protocol():
    alice = User("Alice")
    bob = User("Bob")

    # A->B
    # Send "p", "g", "A"
    alice.init_dh()
    alice.send(bob, MessageType.CH34_DH_SETUP, (DH_2048_MODP[0], DH_2048_MODP[1], alice.public_key))
    assert (
        hasattr(alice, "private_key")
        and hasattr(alice, "public_key")
        and hasattr(alice, "get_secret")
        and hasattr(alice, "get_enc_keys")
    )

    # B->A
    # Send "B"
    bob.read()
    bob.send(alice, MessageType.CH34_DH_SETUP, ("", "", bob.public_key))
    assert (
        hasattr(bob, "private_key")
        and hasattr(bob, "public_key")
        and hasattr(bob, "get_secret")
        and hasattr(bob, "get_enc_keys")
        and hasattr(bob, "foreign_key")
        and bob.foreign_key == alice.public_key
    )

    # A->B
    # Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    alice.read()
    message = b"Hello Bob !"
    iv = randbytes(16)
    alice.send(bob, MessageType.CH34_AES_MSG, (
        encrypt_aes128_cbc(message, alice.get_enc_keys(alice.foreign_key)[0], iv).hex(),
        iv.hex()
    ))
    assert alice.foreign_key == bob.public_key

    # B->A
    # Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    d_m, iv = bob.read()
    iv = randbytes(16)
    bob.send(alice, MessageType.CH34_AES_MSG, (
        encrypt_aes128_cbc(d_m.encode(), bob.get_enc_keys(bob.foreign_key)[0], iv).hex(),
        iv.hex()
    ))
    assert d_m == message.decode()

    # Alice read
    d_m, _ = alice.read()
    assert d_m == message.decode()

    print('='*20)


def test():
    alice = User("Alice")
    bob = User("Bob")
    eve = User("Eve")

    # A->M
    # Send "p", "g", "A"
    alice.init_dh()
    alice.send(eve, MessageType.CH34_DH_SETUP, (DH_2048_MODP[0], DH_2048_MODP[1], alice.public_key))

    # M->B
    # Send "p", "g", "p"
    p, g, _ = eve.read()
    eve.send(bob, MessageType.CH34_DH_SETUP, (p, g, p))

    # B->M
    # Send "B"
    bob.read()
    bob.send(eve, MessageType.CH34_DH_SETUP, ("", "", bob.public_key))

    # M->A
    # Send "p"
    eve.read()
    eve.foreign_key = p
    eve.send(alice, MessageType.CH34_DH_SETUP, ("", "", p))

    # A->M
    # Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
    alice.read()

    assert (
        alice.get_secret(alice.foreign_key)
        == bob.get_secret(bob.foreign_key)
        == eve.get_secret(eve.foreign_key)
    )

    message = b"Hello Bob !"
    iv = randbytes(16)
    alice.send(eve, MessageType.CH34_AES_MSG, (
        encrypt_aes128_cbc(message, alice.get_enc_keys(alice.foreign_key)[0], iv).hex(),
        iv.hex()
    ))

    # M->B
    # Relay that to B (with a twist !)
    iv = randbytes(16)
    eve.relay(bob, (
        encrypt_aes128_cbc(b"I hate you Bob !", eve.get_enc_keys(eve.foreign_key)[0], iv).hex(),
        iv.hex()
    ))

    # B->M
    # Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
    d_m, iv = bob.read()
    iv = randbytes(16)
    bob.send(eve, MessageType.CH34_AES_MSG, (
        encrypt_aes128_cbc(d_m.encode(), bob.get_enc_keys(bob.foreign_key)[0], iv).hex(),
        iv.hex()
    ))

    # M->A
    # Relay that to A (with a twist !)
    iv = randbytes(16)
    eve.relay(alice, (
        encrypt_aes128_cbc(b"I hate you too Alice !", eve.get_enc_keys(eve.foreign_key)[0], iv).hex(),
        iv.hex()
    ))

    # Alice read
    alice.read()


if __name__ == "__main__":
    test_protocol()
    test()
