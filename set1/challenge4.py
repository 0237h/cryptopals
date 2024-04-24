from challenge3 import break_single_byte_xor_cipher


def test():
    out = (
        "",  # Input string
        "",  # Decoded string
        "",  # Character key
        100.  # English phrase scoring
    )
    for line in open("./set1/challenge_4.txt"):
        line = line.strip()
        decoded, key, score = break_single_byte_xor_cipher(line)

        if out[3] > score:
            out = (line, decoded, key, score)

    print(out)

    # Found after running program successfully first
    assert (out[0] == "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")


if __name__ == '__main__':
    test()
