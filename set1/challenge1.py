from base64 import b64encode


def hex_to_base64(input_hex: bytes) -> bytes:
    return b64encode(input_hex)


def test():
    assert (
        hex_to_base64(
            bytes.fromhex(
                "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
        ) == b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )
