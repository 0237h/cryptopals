from math import ceil, gcd
from secrets import randbelow, randbits, token_bytes
from typing import Optional


def is_probably_prime(n: int, iterations: int = 8) -> bool:
    """Adapted from https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test"""
    assert n > 2, "n must be > 2"

    s = 0
    d = n-1
    while d % 2 == 0:
        d >>= 1
        s += 1
    assert (2**s * d == n-1)

    for _ in range(iterations):
        a = 2 + randbelow(n - 2)
        x = pow(a, d, n)

        if (x == 1) or (x == n - 1):
            continue

        for _ in range(s):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n - 1:
                break

        if x != n-1:
            return False

    return True


def generate_prime(n_bits: int = 1024) -> int:
    """From https://crypto.stackexchange.com/a/1971"""
    n = 0
    # Generate odd integer
    while n % 2 == 0:
        n = randbits(n_bits)

    while not is_probably_prime(n):
        n += 2

    return n


def invmod(a: int, b: int) -> int:
    return pow(a, -1, b)


def rsaes_pkcs1_v1_5(public_key: tuple[int, int], message: bytes) -> bytes:
    """From https://datatracker.ietf.org/doc/html/rfc8017#section-7.2"""
    _, n = public_key
    k = ceil(n.bit_length() / 8)
    mLen = len(message)

    assert mLen <= k - 11, "message too long"
    ps = token_bytes(k - mLen - 3)
    while b'\x00' in ps:
        # Must not contain null bytes
        ps = token_bytes(k - mLen - 3)

    return (b"\x00\x02" + ps + b'\x00' + message)


def i2osp(x: int, xLen: int) -> bytes:
    """
    From https://datatracker.ietf.org/doc/html/rfc8017#section-4.1
    Also see
    https://github.com/Legrandin/pycryptodome/blob/f65ae19b3f8c9b4213ccad6df403c6849d0e393f/lib/Crypto/Util/number.py#L407
    """
    return x.to_bytes(xLen)


def os2ip(x: bytes) -> int:
    """
    From https://datatracker.ietf.org/doc/html/rfc8017#section-4.2
    Also see
    https://github.com/Legrandin/pycryptodome/blob/f65ae19b3f8c9b4213ccad6df403c6849d0e393f/lib/Crypto/Util/number.py#L475
    """
    return int.from_bytes(x)


def rsa(key_size_bits: int = 1024, e: int = 65537, pq: Optional[tuple[int, int]] = None):
    """Adapted from https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_generation"""
    p, q = pq if pq else (generate_prime(key_size_bits), generate_prime(key_size_bits))
    # Need to make sure `e` and `et` will be coprime (see https://crypto.stackexchange.com/a/12256)
    while gcd(p-1, e) != 1 or gcd(q-1, e) != 1:
        p, q = generate_prime(key_size_bits), generate_prime(key_size_bits)

    n = p * q
    et = (p-1)*(q-1)
    d = invmod(e, et)

    key_size_bytes = ceil(key_size_bits / 4)  # N is multiple of two `key_size_bits` number so only divide by 4

    def _encrypt(plaintext: bytes, public_key: tuple[int, int] = (e, n), use_padding: bool = True):
        """From https://datatracker.ietf.org/doc/html/rfc8017#section-7.2.1"""
        assert len(plaintext) <= key_size_bytes, f"encryption error: can only encrypt {key_size_bytes-1} bytes at a time"  # noqa

        m = os2ip(rsaes_pkcs1_v1_5(public_key, plaintext)) if use_padding else os2ip(plaintext)
        c = pow(m, *public_key)

        return i2osp(c, key_size_bytes)

    def _decrypt(ciphertext: bytes, use_padding: bool = True, strip_null_bytes: bool = True):
        """From https://datatracker.ietf.org/doc/html/rfc8017#section-7.2.2"""
        assert len(ciphertext) == key_size_bytes, "decryption error: ciphertext length doesn't match key size"

        c = os2ip(ciphertext)
        m = pow(c, d, n)
        em = i2osp(m, key_size_bytes)

        if not use_padding:
            return em.strip(b'\x00') if strip_null_bytes else em

        # Warning: padding check not timing resistant
        assert em[0] == 0x0 \
            and em[1] == 0x2 \
            and em.find(b'\x00', 2) != -1 \
            and em.find(b'\x00', 2) > 9, "decryption error"
        return em[em.find(b'\x00', 2)+1:]

    return (
        key_size_bits,
        (e, n),  # Public key
        (d, n),  # Private key
        _encrypt,
        _decrypt
    )


def test_primality():
    assert is_probably_prime(3)
    assert is_probably_prime(5)
    assert is_probably_prime(7)
    assert is_probably_prime(820009863367164719528728036109)
    assert not is_probably_prime(8200098633671647195287280361092)
    assert is_probably_prime(int(
        '91194053720802038749867895653760357173570191653702330141610008197774255234754355027884261275550865474712718006'
        '65903108731123489323220418930940845107472269844249951431800623491080897468055706948025657160986588400779040986'
        '13114700915101228094152825654183356049864119636990754020947963143920091855081833'
    ))
    assert not is_probably_prime(int(
        '91194053720802038749867895653760357173570191653702330141610008197774255234754355027884261275550865474712718006'
        '65903108731123489323220418930940845107472269844249951431800623491080897468055706948025657160986588400779040986'
        '131147009151012280941528256541833560498641196369907540209479631439200918550818332'
    ))


def test_invmod():
    assert invmod(17, 3120) == 2753
    assert invmod(42, 2017) == 1969


def test():
    print(f"[x] Generating RSA keys...")
    key_length, pub_key, priv_key, enc, dec = rsa()

    print(f"[*] Key length: {key_length} bits")
    print(f"[*] Public key: {pub_key}")
    print(f"[*] Private key: {priv_key}")

    message = b"Hello world !"
    ciphertext = enc(message)
    print(f"[*] Ciphertext: {ciphertext.hex()}")

    plaintext = dec(ciphertext)
    assert plaintext == message
    print(f"[+] Plaintext: {plaintext.decode()}")


if __name__ == "__main__":
    test_primality()
    test_invmod()
    test()
