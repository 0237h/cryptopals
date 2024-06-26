# Reference:
# ==========
# National Institute of Standards and Technology (2001) Advanced Encryption
# Standard (AES). (Department of Commerce, Washington, D.C.), Federal Infor-
# mation Processing Standards Publication (FIPS) NIST FIPS 197-upd1, updated
# May 9, 2023. https://doi.org/10.6028/NIST.FIPS.197-upd1


from typing import List
from base64 import b64decode

sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

sboxInv = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def __print_block(block: bytearray | bytes):
    assert len(block) % 4 == 0
    print(' '.join(block[i:i+4].hex().upper() for i in range(0, len(block), 4)))


def __gal_mul(a: int, b: int) -> int:
    """
    Multiplication in Gallois Field GF(2^8).
    Adapted from https://en.wikipedia.org/wiki/Finite_field_arithmetic
    """
    r = 0
    for _ in range(8):
        r ^= -(b & 1) & a
        mask = -((a >> 7) & 1)
        # 0b1_0001_1011 is x^8 + x^4 + x^3 + x + 1
        a = ((a << 1) ^ (0b1_0001_1011 & mask)) & 0xFF
        b >>= 1

    return r


gal_2 = [__gal_mul(0x2, x) for x in range(256)]
gal_3 = [__gal_mul(0x3, x) for x in range(256)]
gal_e = [__gal_mul(0xe, x) for x in range(256)]
gal_b = [__gal_mul(0xb, x) for x in range(256)]
gal_d = [__gal_mul(0xd, x) for x in range(256)]
gal_9 = [__gal_mul(0x9, x) for x in range(256)]


def _keyExpansion(key: bytes) -> List[bytes]:
    def __subWord(w: bytes) -> bytes:
        return bytes([sbox[w[0]], sbox[w[1]], sbox[w[2]], sbox[w[3]]])

    def __rotWord(w: bytes) -> bytes:
        bw = bytearray(w)
        bw.append(w[0])
        return bw[1:]

    keys = []
    for i in range(4):
        keys.append(key[i*4:(i+1)*4])

    for i in range(4, 44):
        tmp = keys[i-1]
        if (i % 4) == 0:
            tmp = (int.from_bytes(__subWord(__rotWord(tmp))) ^ rcon[i//4] << 24).to_bytes(4)

        keys.append((int.from_bytes(keys[i-4]) ^ int.from_bytes(tmp)).to_bytes(4))

    return keys


def _addRoundKey(state: bytearray, key: bytes) -> bytearray:
    assert len(state) == len(key), f"\nKey = {key.hex()}\nState = {state.hex()}\n"
    for i in range(len(state)):
        state[i] ^= key[i]

    return state


def _subBytes(state: bytearray) -> bytearray:
    for i in range(len(state)):
        state[i] = sbox[state[i]]

    return state


def _invSubBytes(state: bytearray) -> bytearray:
    for i in range(len(state)):
        state[i] = sboxInv[state[i]]

    return state


def _shiftRows(state: bytearray) -> bytearray:
    # Shift first row by 1 left
    tmp = state[1]
    state[1] = state[5]
    state[5] = state[9]
    state[9] = state[13]
    state[13] = tmp
    # Shift second row by 2 left (same as swapping)
    state[2], state[10] = state[10], state[2]
    state[6], state[14] = state[14], state[6]
    # Shift third row by 3 left
    tmp = state[3]
    state[3] = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = tmp

    return state


def _invShiftRows(state: bytearray) -> bytearray:
    # Shift first row by 1 right
    tmp = state[13]
    state[13] = state[9]
    state[9] = state[5]
    state[5] = state[1]
    state[1] = tmp
    # Shift second row by 2 right (same as swapping)
    state[2], state[10] = state[10], state[2]
    state[6], state[14] = state[14], state[6]
    # Shift third row by 3 right
    tmp = state[3]
    state[3] = state[7]
    state[7] = state[11]
    state[11] = state[15]
    state[15] = tmp

    return state


def _mixColumns(state: bytearray) -> bytearray:
    for i in range(4):
        x1, x2, x3, x4 = state[i*4:(i+1)*4]
        state[i*4] = __gal_mul(0x2, x1) ^ __gal_mul(0x3, x2) ^ x3 ^ x4
        state[i*4 + 1] = x1 ^ __gal_mul(0x2, x2) ^ __gal_mul(0x3, x3) ^ x4
        state[i*4 + 2] = x1 ^ x2 ^ __gal_mul(0x2, x3) ^ __gal_mul(0x3, x4)
        state[i*4 + 3] = __gal_mul(0x3, x1) ^ x2 ^ x3 ^ __gal_mul(0x2, x4)

    return state


def _invMixColumns(state: bytearray) -> bytearray:
    for i in range(4):
        x1, x2, x3, x4 = state[i*4:(i+1)*4]
        state[i*4] = __gal_mul(0xe, x1) ^ __gal_mul(0xb, x2) ^ __gal_mul(0xd, x3) ^ __gal_mul(0x9, x4)
        state[i*4 + 1] = __gal_mul(0x9, x1) ^ __gal_mul(0xe, x2) ^ __gal_mul(0xb, x3) ^ __gal_mul(0xd, x4)
        state[i*4 + 2] = __gal_mul(0xd, x1) ^ __gal_mul(0x9, x2) ^ __gal_mul(0xe, x3) ^ __gal_mul(0xb, x4)
        state[i*4 + 3] = __gal_mul(0xb, x1) ^ __gal_mul(0xd, x2) ^ __gal_mul(0x9, x3) ^ __gal_mul(0xe, x4)

    return state


def _mixColumnsLookup(state: bytearray) -> bytearray:
    for i in range(4):
        x1, x2, x3, x4 = state[i*4:(i+1)*4]
        state[i*4] = gal_2[x1] ^ gal_3[x2] ^ x3 ^ x4
        state[i*4 + 1] = x1 ^ gal_2[x2] ^ gal_3[x3] ^ x4
        state[i*4 + 2] = x1 ^ x2 ^ gal_2[x3] ^ gal_3[x4]
        state[i*4 + 3] = gal_3[x1] ^ x2 ^ x3 ^ gal_2[x4]

    return state


def _invMixColumnsLookup(state: bytearray) -> bytearray:
    for i in range(4):
        x1, x2, x3, x4 = state[i*4:(i+1)*4]
        state[i*4] = gal_e[x1] ^ gal_b[x2] ^ gal_d[x3] ^ gal_9[x4]
        state[i*4 + 1] = gal_9[x1] ^ gal_e[x2] ^ gal_b[x3] ^ gal_d[x4]
        state[i*4 + 2] = gal_d[x1] ^ gal_9[x2] ^ gal_e[x3] ^ gal_b[x4]
        state[i*4 + 3] = gal_b[x1] ^ gal_d[x2] ^ gal_9[x3] ^ gal_e[x4]

    return state


def _aes128(bytes_in: bytes, round_keys: List[bytes]) -> bytes:
    state = bytearray(bytes_in)
    state = _addRoundKey(state, bytes().join(round_keys[:4]))

    for r in range(1, 10):
        state = _subBytes(state)
        state = _shiftRows(state)
        state = _mixColumnsLookup(state)
        state = _addRoundKey(state, bytes().join(round_keys[r*4:(r+1)*4]))

    state = _subBytes(state)
    state = _shiftRows(state)
    state = _addRoundKey(state, bytes().join(round_keys[40:]))

    return state


def _invAes128(bytes_in: bytes, round_keys: List[bytes]) -> bytes:
    state = bytearray(bytes_in)
    state = _addRoundKey(state, bytes().join(round_keys[40:]))

    for r in range(1, 10)[::-1]:
        state = _invShiftRows(state)
        state = _invSubBytes(state)
        state = _addRoundKey(state, bytes().join(round_keys[r*4:(r+1)*4]))
        state = _invMixColumnsLookup(state)

    state = _invShiftRows(state)
    state = _invSubBytes(state)
    state = _addRoundKey(state, bytes().join(round_keys[:4]))

    return state


def encrypt_aes128_ecb(plaintext: bytes, key: bytes) -> bytearray:
    assert len(key) == 16, "Key must be 128 bits"

    padding_bytes = 16 - (len(plaintext) % 16)

    plaintext = bytearray(plaintext)
    plaintext.extend([padding_bytes] * padding_bytes)

    output_bytes = bytearray()
    keys = _keyExpansion(key)

    for x in [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]:
        output_bytes.extend(_aes128(x, keys))

    return output_bytes


def decrypt_aes128_ecb(ciphertext: bytes, key: bytes) -> bytearray:
    assert len(key) == 16, "Key must be 128 bits"

    output_bytes = bytearray()
    keys = _keyExpansion(key)

    for x in [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]:
        output_bytes.extend(_invAes128(x, keys))

    padding_byte = output_bytes[-1]  # Detect PKCS7 padding byte to truncate output
    return output_bytes[:-padding_byte]


def encrypt_aes128_ecb_str(plaintext: str, key: str) -> str:
    return encrypt_aes128_ecb(plaintext.encode(), key.encode()).hex()


def decrypt_aes128_ecb_str(ciphertext: str, key: str) -> str:
    return decrypt_aes128_ecb(bytes.fromhex(ciphertext), key.encode()).decode()


def test():
    plaintext = "Hello World!"
    key = "YELLOW SUBMARINE"
    cipher = encrypt_aes128_ecb_str(plaintext, key)
    recovered = decrypt_aes128_ecb_str(cipher, key)

    assert (plaintext == recovered)

    cipherfile = open("./set1/challenge_7.txt", "rb").read()
    recovered_cipherfile = decrypt_aes128_ecb(b64decode(cipherfile), key.encode()).decode()

    assert (recovered_cipherfile[:33] == "I'm back and I'm ringin' the bell")
    print(recovered_cipherfile)


if __name__ == "__main__":
    test()
