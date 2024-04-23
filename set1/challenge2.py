def xor(left: bytes, right: bytes) -> bytes:
    if (len(left) != len(right)):
        raise ValueError("`left` and `right` must be of the same length")

    return bytes(a ^ b for a, b in zip(left, right))


def test():
    assert (
        xor(
            bytes.fromhex("1c0111001f010100061a024b53535009181c"),
            bytes.fromhex("686974207468652062756c6c277320657965")
        ).hex() == "746865206b696420646f6e277420706c6179"
    )
