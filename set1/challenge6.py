from base64 import b64decode
from typing import Tuple
from challenge5 import repeating_key_xor
from challenge3 import break_single_byte_xor_cipher
from math import gcd
from itertools import combinations


MIN_KEYSIZE = 2
MAX_KEYSIZE = 40
TOP_N_HAMMINGS = 5


def hamming_distance(a: bytes, b: bytes) -> int:
    if (len(a) != len(b)):
        raise ValueError("`a` and `b` must be of the same length")

    return sum([z.bit_count() for z in [x ^ y for (x, y) in zip(a, b)]])


def test_hamming():
    assert (hamming_distance("this is a test".encode(), "wokka wokka!!!".encode()) == 37)


def find_probable_key_lengths(
    ciphertext: bytes,
    min_keysize=MIN_KEYSIZE,
    max_keysize=MAX_KEYSIZE,
    top_n_hammings=TOP_N_HAMMINGS
) -> set[int]:
    """
    Using Hamming distances to compute a set of most probable key length for the ciphertext.
    Featuring GCD calculations for improved accuracy.
    """
    ciphertext_len = len(ciphertext)
    min_hammings = []
    max_range = min(ciphertext_len // 2, max_keysize) + 1

    for keysize in range(min_keysize, max_range):
        chunks = [ciphertext[i:i+keysize] for i in range(0, ciphertext_len, keysize)]

        # Make sure we have all pairs of chunks of same size
        if (len(chunks) % 2 or len(chunks[-1]) != len(chunks[-2])):
            chunks.pop()

        d = 0
        for k in range(0, len(chunks) - 1, 2):
            d += hamming_distance(chunks[k], chunks[k+1])

        d /= len(chunks) / 2 * keysize  # Normalize hamming distance

        # Keep track of `top_n_hammings` distances for calculating probable keys
        if (len(min_hammings) < top_n_hammings):
            min_hammings.append((keysize, d))
            min_hammings = sorted(min_hammings, key=lambda x: x[1])
        elif (d < min_hammings[-1][1]):  # Needs list to be sorted
            min_hammings.pop()
            min_hammings.append((keysize, d))
            min_hammings = sorted(min_hammings, key=lambda x: x[1])

    probable_key_lengths = {min_hammings[0][0]}  # Add key length with lowest hamming score
    k = 1
    i = 0
    while (k == 1 and i+1 < len(min_hammings)):
        k = gcd(min_hammings[i][0], min_hammings[i+1][0])
        i += 1

    probable_key_lengths.add(k)  # Add first GCD != 1 for pair of key length with lowest hamming score

    k = min_hammings[0][0]
    for i, j in list(combinations(range(len(min_hammings)), 2)):
        g = gcd(min_hammings[i][0], min_hammings[j][0])
        if g > 1:
            k = min(k, g)

    probable_key_lengths.add(k)  # Add minimum GCD of all key length pairs
    probable_key_lengths.add(max(probable_key_lengths) // min(probable_key_lengths))  # Works also sometimes :)

    print(f"[+] Found probable key lengths: {probable_key_lengths}")
    return probable_key_lengths


def break_repeating_key_xor(ciphertext: bytes, known_key_length=None) -> Tuple[str, str]:
    ciphertext_len = len(ciphertext)
    print(f"[*] Cipher:\n{ciphertext.hex()}")
    print(f"[*] Length: {ciphertext_len}")

    if (ciphertext_len < 2*MIN_KEYSIZE):
        raise ValueError(f"[-] Ciphertext length must be greater or equal to {2*MIN_KEYSIZE}")

    plaintext = ""
    cipherkey = bytearray()

    for keysize in find_probable_key_lengths(ciphertext) if not known_key_length else {known_key_length}:
        chunks = [ciphertext[i:i+keysize] for i in range(0, ciphertext_len, keysize)]
        chunks[-1] = chunks[-1] + b'*'*(keysize - len(chunks[-1]))  # Fill last chunk with filler bytes

        # Transpose chunks
        chunks_t = list(zip(*chunks))

        cipherkey = bytearray()
        for (_, key, _) in [break_single_byte_xor_cipher(bytes(c).hex()) for c in chunks_t]:
            cipherkey += ord(key).to_bytes()

        if not cipherkey:
            continue

        try:
            plaintext = repeating_key_xor(ciphertext, cipherkey).decode()
        except UnicodeError:
            print(f"[*] Skipping keysize={keysize} due to Unicode decoding errors")
            continue

        print(f"[+] Recovered key (keysize={keysize}): {cipherkey}")
        print(f"[*] Decoded:\n{plaintext}")
        if (known_key_length or input("[?] Continue ? [Y/n]\n").lower() == 'n'):
            break

    print("[+] Done !")
    return (cipherkey.decode(errors="backslashreplace"), plaintext)


def test():
    ciphertext = b64decode(open("./set1/challenge_6.txt", 'rb').read())
    key, plain = break_repeating_key_xor(ciphertext, 29)

    assert (key == "Terminator X: Bring the noise")
    assert (plain[:33] == "I'm back and I'm ringin' the bell")


if __name__ == '__main__':
    test_hamming()
    test()
