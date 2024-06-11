from secrets import token_bytes, randbelow
from challenge28 import _compute_message_padding, sha1, mac_sha1

KEY = token_bytes(randbelow(128))


def validate_mac(message: bytes, mac: bytes) -> bool:
    return mac_sha1(KEY, message) == mac


def test():
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    message_hash = mac_sha1(
        KEY,
        message
    )

    secret_key_length = 0
    padding = b""
    forged = b";admin=true"
    new_hash = b""
    internal_state = (
        int.from_bytes(message_hash[:4]),
        int.from_bytes(message_hash[4:8]),
        int.from_bytes(message_hash[8:12]),
        int.from_bytes(message_hash[12:16]),
        int.from_bytes(message_hash[16:]),
    )

    target_hash = mac_sha1(KEY, message + _compute_message_padding(KEY + message) + forged)
    print(f"[*] Secret key (length = {len(KEY)}):\n{KEY.hex()}")
    print(f"[*] Target: {target_hash.hex()}")

    while not validate_mac(message + padding + forged, new_hash):
        secret_key_length += 1
        padding = _compute_message_padding(b'A'*(secret_key_length + len(message)))

        new_hash = sha1(
            forged,
            internal_state,
            _compute_message_padding(b'A'*(secret_key_length + len(message) + len(padding) + len(forged)))
        )

        print(f"[x] Testing secret key length = {secret_key_length}: {new_hash.hex()}", end='\r')

    print()
    print(f"[+] Matched MAC:\n{message + padding + forged}\n{mac_sha1(KEY, message + padding + forged).hex()}")


if __name__ == "__main__":
    test()
