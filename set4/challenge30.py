from secrets import token_bytes, randbelow
from typing import Callable, Optional, Sequence
from challenge28 import BLOCK_SIZE_BYTES, _circular_left_shift, _compute_message_padding

BLOCK_SIZE_WORDS = BLOCK_SIZE_BYTES // 4
KEY = token_bytes(randbelow(128))


def _changeEndianness(x: int) -> int:
    '''From https://rosettacode.org/wiki/MD4#C'''
    return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >> 8) | ((x & 0xFF000000) >> 24)


def convert_padding_sha1_to_md4(message: bytes) -> bytes:
    return message[:-8] + message[-4:][::-1] + message[-8:-4][::-1]


def md4(
    message: bytes,
    internal_state: tuple[int, int, int, int] = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476),
    padding: Optional[bytes] = None
) -> bytes:
    message += padding if padding else _compute_message_padding(message)
    # Swap message length (last 2 words) endianness
    message = convert_padding_sha1_to_md4(message)
    a, b, c, d = internal_state

    def _f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def _g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def _h(x: int, y: int, z: int) -> int:
        return (x ^ y ^ z)

    def _round1(a: int, b: int, c: int, d: int, xk: int, s: int) -> int:
        return _circular_left_shift((a + _f(b, c, d) + xk) & 0xFFFFFFFF, s)

    def _round2(a: int, b: int, c: int, d: int, xk: int, s: int) -> int:
        return _circular_left_shift((a + _g(b, c, d) + xk + 0x5A827999) & 0xFFFFFFFF, s)

    def _round3(a: int, b: int, c: int, d: int, xk: int, s: int) -> int:
        return _circular_left_shift((a + _h(b, c, d) + xk + 0x6ED9EBA1) & 0xFFFFFFFF, s)

    def _round(
        f: Callable[[int, int, int, int, int, int], int],
        a: int, b: int, c: int, d: int,
        chunk: Sequence[int], ss: Sequence[int], kk: Sequence[int]
    ):
        assert len(kk) == BLOCK_SIZE_WORDS
        assert len(ss) == 4

        for i in range(0, BLOCK_SIZE_WORDS, 4):
            a = f(a, b, c, d, chunk[kk[i]], ss[i % 4])
            d = f(d, a, b, c, chunk[kk[i + 1]], ss[(i+1) % 4])
            c = f(c, d, a, b, chunk[kk[i + 2]], ss[(i+2) % 4])
            b = f(b, c, d, a, chunk[kk[i + 3]], ss[(i+3) % 4])

        return (a, b, c, d)

    chunks = [message[k:k+BLOCK_SIZE_BYTES] for k in range(0, len(message), BLOCK_SIZE_BYTES)]
    for chunk in chunks:
        # Convert to 16 words (little endian !)
        chunk = list([int.from_bytes(chunk[k:k+4], "little") for k in range(0, BLOCK_SIZE_BYTES, 4)])
        assert len(chunk) == BLOCK_SIZE_WORDS

        aa = a
        bb = b
        cc = c
        dd = d

        a, b, c, d = _round(_round1, a, b, c, d, chunk, [3, 7, 11, 19], list(range(BLOCK_SIZE_WORDS)))
        a, b, c, d = _round(_round2, a, b, c, d, chunk, [3, 5, 9, 13],
                            [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
                            )
        a, b, c, d = _round(_round3, a, b, c, d, chunk, [3, 9, 11, 15],
                            [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
                            )

        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    a = _changeEndianness(a)
    b = _changeEndianness(b)
    c = _changeEndianness(c)
    d = _changeEndianness(d)

    return ((a << 96) | (b << 64) | (c << 32) | d).to_bytes(16)


def mac_md4(key: bytes, message: bytes) -> bytes:
    return md4(key + message)


def validate_mac(message: bytes, mac: bytes) -> bool:
    return mac_md4(KEY, message) == mac


def test_md4():
    # From https://raw.githubusercontent.com/rpicard/py-md4/master/md4-test-vectors.txt
    assert md4(b'').hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert md4(b'a').hex() == "bde52cb31de33e46245e05fbdbd6fb24"
    assert md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    assert md4(b"message digest").hex() == "d9130a8164549fe818874806e1c7014b"
    assert md4(b"abcdefghijklmnopqrstuvwxyz").hex() == "d79e1c308aa5bbcdeea8ed63df412da9"
    assert (md4(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").hex()
            == "043f8582f241db351ce627e153e7f0e4")
    assert (md4(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890").hex()
            == "e33b4ddc9c38f2199c3e7b164fcc0536")


def test():
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    message_hash = mac_md4(
        KEY,
        message
    )

    secret_key_length = len(KEY) - 1
    padding = b""
    forged = b";admin=true"
    new_hash = b""
    internal_state = (
        int.from_bytes(message_hash[:4], "little"),
        int.from_bytes(message_hash[4:8], "little"),
        int.from_bytes(message_hash[8:12], "little"),
        int.from_bytes(message_hash[12:], "little")
    )

    target_hash = mac_md4(KEY, message + convert_padding_sha1_to_md4(_compute_message_padding(KEY + message)) + forged)
    print(f"[*] Secret key (length = {len(KEY)}):\n{KEY.hex()}")
    print(f"[*] Target: {target_hash.hex()}")

    while not validate_mac(message + padding + forged, new_hash) and secret_key_length < len(KEY) + 1:
        secret_key_length += 1
        padding = convert_padding_sha1_to_md4(_compute_message_padding(b'A'*(secret_key_length + len(message))))

        new_hash = md4(
            forged,
            internal_state,
            _compute_message_padding(b'A'*(secret_key_length + len(message) + len(padding) + len(forged)))
        )

        print(f"[x] Testing secret key length = {secret_key_length}: {new_hash.hex()}", end='\r')

    print()
    print(f"[+] Matched MAC:\n{message + padding + forged}\n{mac_md4(KEY, message + padding + forged).hex()}")


if __name__ == "__main__":
    test_md4()
    test()
