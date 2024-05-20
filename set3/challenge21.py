from typing import List, Optional

MT19937_PARAMETERS = (32, 624, 397, 31, 0x9908b0df, 11, 0xffffffff, 7, 0x9d2c5680, 15, 0xefc60000, 18, 1812433253)
MT19937_64_PARAMETERS = (64, 312, 156, 31, 0xb5026f5aa96619e9, 29, 0x5555555555555555, 17, 0x71d67fffeda60000, 37,
                         0xfff7eee000000000, 43, 6364136223846793005)


def mt(w, n, m, r, a, u, d, s, b, t, c, l, f, state: Optional[List[int]] = None):
    """Adapted pseudocode of https://en.wikipedia.org/w/index.php?title=Mersenne_Twister&oldid=1124934461#Pseudocode"""
    MT = [0 for _ in range(n)]
    # Allow setting generator state
    if state and len(state) == n:
        MT = [k for k in state]

    index = n+1
    w_bit_mask = int('1'*w, 2)
    lower_mask = (1 << r) - 1  # That is, the binary number of r 1's
    upper_mask = w_bit_mask & (~lower_mask)

    def _twist():
        """Generate the next n values from the series x_i"""
        nonlocal index, MT
        for i in range(n):
            x = (MT[i] & upper_mask) | (MT[(i+1) % n] & lower_mask)
            xA = x >> 1
            if (x % 2) != 0:  # lowest bit of x is 1
                xA = xA ^ a
            MT[i] = MT[(i + m) % n] ^ xA
        index = 0

    def seed_mt(seed: int):
        """Initialize the generator from a seed"""
        nonlocal index, MT
        index = n
        MT[0] = seed
        for i in range(1, n):
            MT[i] = w_bit_mask & (f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i)

    def extract_number():
        """Extract a tempered value based on MT[index] calling twist() every n numbers"""
        nonlocal index
        if index >= n:
            if index > n and not state:
                # Alternatively, seed with constant value; 5489 is used in reference C code[54]
                print("[!] Generator was never seeded")
            _twist()

        y = MT[index]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)

        index += 1
        return w_bit_mask & y

    return (seed_mt, extract_number)


def mt19937(seed: int):
    # From https://en.cppreference.com/w/cpp/numeric/random/mersenne_twister_engine
    s, e = mt(*MT19937_PARAMETERS)

    s(seed)
    while True:
        yield e()


def mt19937_64(seed: int):
    # From https://en.cppreference.com/w/cpp/numeric/random/mersenne_twister_engine
    s, e = mt(*MT19937_64_PARAMETERS)

    s(seed)
    while True:
        yield e()


def test():
    # Output for seed = 1 cross-checked with official C implementation at
    # http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/MT2002/CODES/mt19937ar.c
    assert (next(mt19937(1)) == 1791095845)


if __name__ == "__main__":
    test()
