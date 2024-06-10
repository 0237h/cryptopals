# SHA-1 blocks are 512 bits = 16 words with 1 word = 4 bytes
BLOCK_SIZE_BYTES = 64
BLOCK_SIZE_BITS = BLOCK_SIZE_BYTES * 8


def _circular_left_shift(word: int, n: int, shift_max: int = 32) -> int:
    assert n <= shift_max and n >= 0, f"n must be between 0 <= n <= {shift_max}"
    assert word.bit_length() <= shift_max, f"word cannot be greater than {shift_max}"

    mask = int('1' * shift_max, 2)
    return (((word << n) & mask) | (word >> (shift_max - n))) & mask


def sha1(message: bytes) -> bytes:
    message_len_bits = 8*len(message)

    # Last 64 bits are reserved for the original message length
    padding = '1' + '0'*(BLOCK_SIZE_BITS - 65 - (message_len_bits % BLOCK_SIZE_BITS))
    padding = int(padding, 2).to_bytes(max(1, len(padding) // 8))

    message = message + padding + message_len_bits.to_bytes(8)

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    for chunk in [message[k:k+BLOCK_SIZE_BYTES] for k in range(0, len(message), BLOCK_SIZE_BYTES)]:
        chunk_words = list([int.from_bytes(chunk[k:k+4]) for k in range(0, BLOCK_SIZE_BYTES, 4)])
        assert len(chunk_words) == 16, f"Failed to break chunk into 16 words: got length of {len(chunk_words)}"

        # Extend to 80 words
        chunk_words += [0] * 64
        for i in range(16, 80):
            chunk_words[i] = _circular_left_shift(
                chunk_words[i-3] ^ chunk_words[i-8] ^ chunk_words[i-14] ^ chunk_words[i-16],
                1
            )

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif i >= 20 and i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i >= 40 and i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (_circular_left_shift(a, 5) + f + e + k + chunk_words[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = _circular_left_shift(b, 30)
            b = a
            a = temp

        # Additions modulo 2^32
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    return ((h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4).to_bytes(20)


def mac_sha1(key: bytes, message: bytes):
    return sha1(key + message)


def test_left_shit():
    a = 0b10010110100101101001011010010000

    # Results cross-checked from:
    # https://onlinetoolz.net/bitshift#base=2&value=10010110100101101001011010010000&bits=32&steps=32&dir=l&type=circ&allsteps=1
    shift_results = [
        a,  # 0 shift
        0b00101101001011010010110100100001,
        0b01011010010110100101101001000010,
        0b10110100101101001011010010000100,
        0b01101001011010010110100100001001,
        0b11010010110100101101001000010010,
        0b10100101101001011010010000100101,
        0b01001011010010110100100001001011,
        0b10010110100101101001000010010110,
        0b00101101001011010010000100101101,
        0b01011010010110100100001001011010,
        0b10110100101101001000010010110100,
        0b01101001011010010000100101101001,
        0b11010010110100100001001011010010,
        0b10100101101001000010010110100101,
        0b01001011010010000100101101001011,
        0b10010110100100001001011010010110,
        0b00101101001000010010110100101101,
        0b01011010010000100101101001011010,
        0b10110100100001001011010010110100,
        0b01101001000010010110100101101001,
        0b11010010000100101101001011010010,
        0b10100100001001011010010110100101,
        0b01001000010010110100101101001011,
        0b10010000100101101001011010010110,
        0b00100001001011010010110100101101,
        0b01000010010110100101101001011010,
        0b10000100101101001011010010110100,
        0b00001001011010010110100101101001,
        0b00010010110100101101001011010010,
        0b00100101101001011010010110100100,
        0b01001011010010110100101101001000,
        a  # 32 shift
    ]

    for i in range(33):
        assert _circular_left_shift(a, i) == shift_results[i]


def test_sha1():
    # NIST test vectors from
    # https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip

    # Len = 0
    assert sha1(b'').hex() == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

    # Len = 8
    assert sha1(bytes.fromhex('36')).hex() == 'c1dfd96eea8cc2b62785275bca38ac261256e278'

    # Len = 16
    assert sha1(bytes.fromhex('195a')).hex() == '0a1c2d555bbe431ad6288af5a54f93e0449c9232'

    # Len = 24
    assert sha1(bytes.fromhex('df4bd2')).hex() == 'bf36ed5d74727dfd5d7854ec6b1d49468d8ee8aa'

    # Len = 32
    assert sha1(bytes.fromhex('549e959e')).hex() == 'b78bae6d14338ffccfd5d5b5674a275f6ef9c717'

    # Len = 40
    assert sha1(bytes.fromhex('f7fb1be205')).hex() == '60b7d5bb560a1acf6fa45721bd0abb419a841a89'

    # Len = 48
    assert sha1(bytes.fromhex('c0e5abeaea63')).hex() == 'a6d338459780c08363090fd8fc7d28dc80e8e01f'

    # Len = 56
    assert sha1(bytes.fromhex('63bfc1ed7f78ab')).hex() == '860328d80509500c1783169ebf0ba0c4b94da5e5'

    # Len = 64
    assert sha1(bytes.fromhex('7e3d7b3eada98866')).hex() == '24a2c34b976305277ce58c2f42d5092031572520'

    # Len = 72
    assert sha1(bytes.fromhex('9e61e55d9ed37b1c20')).hex() == '411ccee1f6e3677df12698411eb09d3ff580af97'

    # Len = 128
    assert sha1(
        bytes.fromhex('3552694cdf663fd94b224747ac406aaf')
    ).hex() == 'a150de927454202d94e656de4c7c0ca691de955d'

    # Len = 136
    assert sha1(
        bytes.fromhex('f216a1cbde2446b1edf41e93481d33e2ed')
    ).hex() == '35a4b39fef560e7ea61246676e1b7e13d587be30'

    # Len = 280
    assert sha1(
        bytes.fromhex('6fda97527a662552be15efaeba32a3aea4ed449abb5c1ed8d9bfff544708a425d69b72')
    ).hex() == '01b4646180f1f6d2e06bbe22c20e50030322673a'

    # Len = 512
    assert sha1(bytes.fromhex(
        '45927e32ddf801caf35e18e7b5078b7f5435278212ec6bb99df884f49b327c6486feae46ba187dc1cc9145121e1492e6b06e9007394dc3'
        + '3b7748f86ac3207cfe'
    )).hex() == 'a70cfbfe7563dd0e665c7c6715a96a8d756950c0'


def test():
    assert mac_sha1(b'', b'').hex() == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

    message = b'abcd'
    assert mac_sha1(b'', message) == sha1(message)
    assert mac_sha1(message[:2], message[2:]) == sha1(message)

    key = b'SECRET'
    assert mac_sha1(key, message + b'TAMPER') != mac_sha1(key, message)


if __name__ == "__main__":
    test_left_shit()
    test_sha1()
    test()
