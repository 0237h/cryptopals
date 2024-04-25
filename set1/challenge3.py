from typing import Tuple
from challenge2 import xor
from collections import defaultdict
from string import printable

# Retrieved from https://en.wikipedia.org/wiki/Letter_frequency
LETTERS_FREQ_EN = {
    "E": 0.127,
    "T": 0.091,
    "A": 0.082,
    "O": 0.075,
    "I": 0.070,
    "N": 0.067,
    "S": 0.063,
    "H": 0.061,
    "R": 0.060,
    "D": 0.043,
    "L": 0.040,
    "C": 0.028,
    "U": 0.028,
    "M": 0.024,
    "W": 0.024,
    "F": 0.022,
    "G": 0.020,
    "Y": 0.020,
    "P": 0.019,
    "B": 0.015,
    "V": 0.0098,
    "K": 0.0077,
    "J": 0.0015,
    "X": 0.0015,
    "Q": 0.00095,
    "Z": 0.00074,
}


def character_frequency(input_string: str) -> dict[str, float]:
    d = defaultdict(int)

    for c in input_string:
        d[c] += 1

    input_string_len = len(input_string)
    return {c: count / input_string_len for c, count in d.items()}


def compute_english_phrase_score(input_string: str) -> float:
    '''
    Sums the differences in frequencies observed in the text from the reference. Lower score (closer to 0) is better.
    '''

    return sum([
        abs(LETTERS_FREQ_EN.get(c.upper(), -10*f) - f)  # Apply big penalty if the letter isn't in the A-Z range
        for c, f in character_frequency(input_string).items()
    ])


def break_single_byte_xor_cipher(input_hex: str) -> Tuple[str, str, float]:
    hex_bytes = bytes.fromhex(input_hex)
    high_score_result = (
        "",  # Decoded string
        "",  # Character key
        100.  # English phrase scoring
    )

    for c in printable:
        decoded = xor(hex_bytes, str.encode(c*len(hex_bytes))).decode(errors="replace")
        score = compute_english_phrase_score(decoded)

        if score < high_score_result[2]:
            high_score_result = (decoded, c, score)

    return high_score_result


def test():
    hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    decoded, key, score = break_single_byte_xor_cipher(hex_string)

    print(f"Input: {hex_string}\nDecoded: {decoded}\nKey: {key}\nScore: {score}")

    # Found after running program successfully first
    assert (key == 'X')


if __name__ == '__main__':
    test()
