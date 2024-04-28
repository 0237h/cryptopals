def pkcs7(block: bytes, pad_length: int) -> bytes:
    padding_bytes = pad_length - (len(block) % pad_length)

    block = bytearray(block)
    block.extend([padding_bytes] * padding_bytes)

    return block


def test():
    assert (pkcs7("YELLOW SUBMARINE".encode(), 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04")
    assert (pkcs7("YELLOW SUBMARINE".encode(), 16) == b"YELLOW SUBMARINE" + b"\x10" * 16)

    text = "YELLOW SUBMARINE"
    padding_length = 20

    print(f"Text: {text} | Text length: {len(text)} | Padding length: {padding_length}")
    print(f"Padded block: {pkcs7(text.encode(), padding_length)}")


if __name__ == "__main__":
    test()
