from math import ceil
from challenge2 import xor


def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    plaintext_len = len(plaintext)
    key_len = len(key)

    if key_len < plaintext_len:
        key = key * ceil(plaintext_len / key_len)

    key = key[:plaintext_len]
    return xor(plaintext, key)


def test():
    assert (
        repeating_key_xor(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal".encode(),
            "ICE".encode()
        ).hex() ==
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a6" +
        "53e2b2027630c692b20283165286326302e27282f"
    )


if __name__ == '__main__':
    test()
