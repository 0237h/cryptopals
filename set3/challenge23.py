from random import getrandbits
from typing import List, Optional
from challenge21 import MT19937_PARAMETERS, mt, mt19937

RANDOM_SEED = getrandbits(32)
MT19937_WORD_SIZE = MT19937_PARAMETERS[0]


def unshift_right(k: int, offset: int, mask: Optional[int] = None) -> int:
    half_word_size = MT19937_WORD_SIZE // 2
    offset_mask = int('1'*offset, 2)

    # Recover XORSHIFT `offset` bits at a time
    # NB: If offset is greater or equal to `half_word_size`, one iteration is sufficient to recover all missing bits
    for i in range(max((half_word_size - offset) + 1, 1), 0, -1):
        z = (k & (offset_mask << i*offset)) >> offset
        k ^= z & (mask if mask else z)

    return k


# Bit reversing for left unshift inspired by @anneouyang's implementation
# https://github.com/anneouyang/MT19937/blob/master/code/clone_mt19937.py
def reverse_bits(x: int) -> int:
    return int(bin(x)[2:].zfill(MT19937_WORD_SIZE)[::-1], 2)


def unshift_left(k: int, offset: int, mask: Optional[int] = None) -> int:
    # Clip to word size
    k &= int('1'*MT19937_WORD_SIZE, 2)

    return reverse_bits(unshift_right(reverse_bits(k), offset, reverse_bits(mask) if mask else None))


def untemper_mt19937(k: int) -> int:
    u, d, s, b, t, c, l = MT19937_PARAMETERS[5:12]

    k = unshift_right(k, l)
    k = unshift_left(k, t, c)
    k = unshift_left(k, s, b)
    k = unshift_right(k, u, d)

    return k


def mt19937_clone(state: List[int]):
    _, e = mt(*MT19937_PARAMETERS, state)

    while True:
        yield e()


def test():
    mt_original = mt19937(RANDOM_SEED)
    state = []

    print(f"[*] Random seed is: {RANDOM_SEED}")
    print(f"[x] Untempering {MT19937_PARAMETERS[1]} states from original...")
    for _ in range(MT19937_PARAMETERS[1]):
        state.append(untemper_mt19937(next(mt_original)))

    mt_clone = mt19937_clone(state)

    assert (next(mt_original) == next(mt_clone))

    print("[+] Successfully cloned MT19937 !")
    print(f"Original (next 10 values):\n{[next(mt_original) for _ in range(10)]}")
    print(f"Clone (next 10 values):\n{[next(mt_clone) for _ in range(10)]}")


def test_unshift():
    y = getrandbits(32)
    mask = getrandbits(32)

    for s in range(2, MT19937_WORD_SIZE + 1):
        assert (y == unshift_right(y ^ (y >> s), s)), f"Failed for shift = {s}"
        assert (y == unshift_right(y ^ ((y >> s) & mask), s, mask)), f"Failed for shift = {s}"
        assert (y == unshift_left(y ^ (y << s), s)), f"Failed for shift = {s}"
        assert (y == unshift_left(y ^ ((y << s) & mask), s, mask)), f"Failed for shift = {s}"


if __name__ == "__main__":
    test_unshift()
    test()
