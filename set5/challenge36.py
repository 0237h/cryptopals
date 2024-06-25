from random import randbytes, randint

from challenge33 import DH_2048_MODP
from challenge34 import Message, MessageType, User as U


import sys
from os import path

sys.path.insert(1, path.abspath("set4"))  # Python hack to resolve set4/ challenges imports

from challenge28 import sha1  # noqa # type: ignore
from challenge31 import hmac_sha1  # noqa # type: ignore

MIN_SALT_BYTES = 16
MAX_SALT_BYTES = 128


def int_to_bytes(x: int) -> bytes:
    return x.to_bytes(length=(max(x.bit_length(), 1) + 7) // 8, byteorder="little")


def sha1_hash(*args) -> int:
    h = bytes()
    for a in args:
        if type(a) is int:
            h += int_to_bytes(a)
        elif type(a) is str:
            h += a.encode()
        elif type(a) is bytes:
            h += a

    return int(sha1(h).hex(), 16)


class User(U):
    def __init__(self, name: str) -> None:
        self.k = 3
        self.server = False
        super().__init__(name)

    def init_dh(self, dh_params: tuple[int, int] = DH_2048_MODP) -> None:
        self.N, self.g = dh_params
        return super().init_dh(dh_params)

    def init_srp(self, email: bytes, password: bytes, dh_params: tuple[int, int] = DH_2048_MODP) -> None:
        self.init_dh(dh_params)
        self.salt = randbytes(randint(MIN_SALT_BYTES, MAX_SALT_BYTES))
        self.v = pow(self.g, sha1_hash(self.salt, email, password), self.N)
        self.server = True  # Identify server from client

    def compute_k(self, email: bytes, password: bytes) -> bytes:
        if self.server:
            self.K = sha1_hash(
                pow(self.foreign_key * pow(self.v, self.u, self.N), self.private_key, self.N)
            )
        else:
            x = sha1_hash(self.salt, email, password)
            self.K = sha1_hash(
                pow(
                    self.foreign_key - self.k * pow(self.g, x, self.N),
                    self.private_key + self.u * x,
                    self.N
                )
            )

        self.K = int_to_bytes(self.K)

        print(f"[*] [{self.name}] Computed K: {self.K.hex()}")
        return self.K

    def _parse(self, message: Message) -> tuple:
        sender, message_type, message_payload = message

        match message_type:
            case MessageType.CH35_SRP_SETUP:
                assert len(message_payload) == 2, \
                    f"[-] Could not parse message (type={message_type}) from {sender}: wrong_payload\n{message_payload}"

                salt, foreign_key = message_payload

                if salt:
                    self.salt = salt

                if foreign_key:
                    self.foreign_key = foreign_key
                    self.u = sha1_hash(*(
                        (self.foreign_key, self.public_key) if self.server
                        else (self.public_key, self.foreign_key)
                    ))

                print(f"[*] [{self.name}] Received SRP params: {(salt, foreign_key)}")
                return (salt, foreign_key)
            case MessageType.CH35_SRP_HMAC:
                assert len(message_payload) == 1, \
                    f"[-] Could not parse message (type={message_type}) from {sender}: wrong_payload\n{message_payload}"

                ref_hmac = message_payload[0]

                print(f"[*] [{self.name}] Received SRP HMAC: {ref_hmac.hex()}")
                hmac = hmac_sha1(self.K, self.salt)
                return (hmac, ref_hmac == hmac)
            case _:
                return super()._parse(message)


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
    carol.send(steve, MessageType.CH35_SRP_SETUP, (None, carol.public_key))

    # S->C
    # Send salt, B=kv + g**b % N
    # Compute string uH = SHA256(A|B), u = integer of uH
    steve.public_key = (steve.public_key + (steve.k * steve.v)) % steve.N  # B=kv + g**b % N
    steve.read()
    steve.send(carol, MessageType.CH35_SRP_SETUP, (steve.salt, steve.public_key))
    carol.read()

    # C, S
    # Generate K = SHA256(S)
    assert carol.compute_k(email, p) == steve.compute_k(email, p)

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
