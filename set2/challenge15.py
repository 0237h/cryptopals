def validate_pkcs7(plaintext: bytes) -> bytes:
    padding_byte = plaintext[-1]

    if not plaintext[-padding_byte:].count(padding_byte) == padding_byte:
        raise ValueError("Not a valid PKCS#7 padding")

    return plaintext[:-padding_byte]


def test():
    plaintext = b"ICE ICE BABY\x04\x04\x04\x04"
    assert (validate_pkcs7(plaintext) == b"ICE ICE BABY")

    print(f"Plaintext:\n{plaintext}")
    print(f"Plaintext (stripped):\n{validate_pkcs7(plaintext)}")

    try:
        validate_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05")
    except ValueError as e:
        assert (str(e) == "Not a valid PKCS#7 padding")

    try:
        validate_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04")
    except ValueError as e:
        assert (str(e) == "Not a valid PKCS#7 padding")


if __name__ == "__main__":
    test()
