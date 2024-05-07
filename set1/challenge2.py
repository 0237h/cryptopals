def xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def test():
    assert (
        xor(
            bytes.fromhex("1c0111001f010100061a024b53535009181c"),
            bytes.fromhex("686974207468652062756c6c277320657965")
        ).hex() == "746865206b696420646f6e277420706c6179"
    )


if __name__ == '__main__':
    test()
