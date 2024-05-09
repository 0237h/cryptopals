from base64 import b64decode
from operator import itemgetter
from string import ascii_letters, whitespace
from typing import List

from challenge18 import encrypt_aes128_ctr

import sys
from os import path

sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge2 import xor  # noqa # type: ignore
from challenge3 import LETTERS_FREQ_EN, character_frequency  # noqa # type: ignore
from challenge8 import find_patterns  # noqa # type: ignore

sys.path.insert(1, path.abspath("set2"))

from challenge11 import random_128  # noqa # type: ignore
from challenge15 import validate_pkcs7  # noqa # type: ignore

RANDOM_KEY = random_128()
COMMON_BIGRAMS = [
    "th", "he", "in", "en", "nt", "re", "er", "an", "ti", "es", "on", "at", "se", "nd", "or", "ar", "al", "te", "co",
    "de", "to", "ra", "et", "ed", "it", "sa", "em", "ro"
]


def english_bigram_count(plaintext: str) -> int:
    return len(
        [bigram for bigram in [plaintext[i:i+2] for i in range(0, len(plaintext), 2)] if bigram in COMMON_BIGRAMS]
    )


def english_score(plaintext: str, is_last_block: List[bool]) -> int:
    freq = character_frequency(plaintext)

    score = 10*len([
        c for i, c in enumerate(plaintext)
        if is_last_block[i] and c not in ascii_letters and c not in whitespace and (ord(c) > 0x10 or ord(c) == 0x0)
    ])

    score += sum([
        abs(LETTERS_FREQ_EN.get(c.upper(), 101*f if c not in ascii_letters and c not in whitespace else 0) - f)
        for c, f in freq.items()
    ])

    return score


def test():
    unknown_strings = [
        b"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        b"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        b"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        b"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        b"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        b"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        b"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        b"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        b"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        b"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        b"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        b"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        b"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        b"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        b"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        b"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        b"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        b"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        b"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        b"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        b"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        b"U2hlIHJvZGUgdG8gaGFycmllcnM/",
        b"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        b"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        b"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        b"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        b"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        b"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        b"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        b"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        b"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        b"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        b"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        b"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        b"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        b"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        b"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        b"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    ]

    ciphertexts = [encrypt_aes128_ctr(b64decode(plaintext), RANDOM_KEY) for plaintext in unknown_strings]
    plaintexts = ["" for _ in range(len(ciphertexts))]
    ciphertexts_len = [len(sample) for sample in ciphertexts]
    max_ciphertexts_len = max(ciphertexts_len)
    block_size = 16

    for b in range(0, max_ciphertexts_len, block_size):
        guess_keystream = bytearray(b'\x00' * block_size)
        actual_keystream = bytearray(b'\x00' * block_size)
        # Store if this iteration corresponds to the last block for the ciphertexts
        is_last_block = [len_ == (b + block_size) for len_ in ciphertexts_len]

        print(f"[x] (b={b}) Finding keystream...")
        for i in range(len(guess_keystream)):
            min_score = 1e8
            for k in range(256):
                guess_keystream[i] = k

                # Working essentially by column of ciphertexts, this approach will struggle for ciphertext that are
                # longer than the majority as we'll have less sample text to analyze.
                sample_text = ''.join([
                    chr(guess_keystream[i] ^ sample[b + i])
                    for sample in ciphertexts if len(sample) > b
                ])

                score = english_score(sample_text, is_last_block)
                if score < min_score:
                    # print(f"Text ({score} > {min_score}): {sample_text}")
                    actual_keystream[i] = k
                    min_score = score

        # Add processing step if any of the plaintexts might contain padding bytes, otherwise we have recovered the
        # entire plaintexts already
        if any(is_last_block):
            # Add this stage we've recovered most the plaintext but the padding bytes are making our scoring fail for
            # the last bytes of plaintext.
            partial_recovered_plaintext = [
                xor(sample[b:b + block_size], actual_keystream).decode(errors='backslashreplace')
                for sample in ciphertexts if len(sample) > b
            ]

            # print(f"[*] Partially recovered plaintexts: {partial_recovered_plaintext}")

            # This next bit of code tries to identify a plaintext with the most padding bytes recovered yet. That way,
            # we can "force" the keystream to align the last remaining bytes to that padding value.

            # List of most repeated character with its count for each partially recovered plaintext, we're hoping to
            # find the padding bytes with this technique.
            plaintext_patterns = [
                max(patterns, key=itemgetter(1)) for patterns in [
                    find_patterns(sample.lower(), 1) for sample in partial_recovered_plaintext
                ]
            ]

            # Find the index of the partial plaintext with the most repeated bytes as it's a likely target for padding
            target_padding, count = max(plaintext_patterns, key=itemgetter(1))
            target_ciphertext = list(
                filter(lambda x: len(x) >= b + block_size, ciphertexts)
            )[plaintext_patterns.index((target_padding, count))]
            target_padding = ord(target_padding)

            if target_padding > 0x10:
                target_padding = count

            # Force the keystream to match the target padding, starting from the last byte of the keystream
            for i in range(1, target_padding + 1):
                for k in range(256):
                    actual_keystream[-i] = k

                    if (actual_keystream[-i] ^ target_ciphertext[-i]) == target_padding:
                        break

        recovered = []
        for sample in ciphertexts:
            if len(sample) > b:
                try:
                    recovered.append(validate_pkcs7(xor(sample[b:b + block_size], actual_keystream)))
                except ValueError:
                    # Invalid PKCS#7 are plaintext that don't correspond to the last block for this sample
                    recovered.append(xor(sample[b:b + block_size], actual_keystream))

        recovered = [r.decode(errors="backslashreplace") for r in recovered]
        print(f"[*] (b={b}) Recovered plaintexts: {recovered}")

        for i in range(len(recovered)):
            plaintexts[i] += recovered[i]

    assert (plaintexts[-1].lower() == "a terrible beauty is born.")

    plaintext = '\n'.join([p.capitalize() for p in plaintexts])
    print(f"[+] Plaintext:\n{plaintext}")


if __name__ == "__main__":
    test()

# near my hea\x16\x1aDmo
# y is born.\x06bhnik
