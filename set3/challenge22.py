import pytest
from time import sleep, time_ns
from random import randint
from challenge21 import mt19937

TARGET_SEED = None


def random_prng():
    global TARGET_SEED
    # Wait a random number of seconds between, I don't know, 40 and 1000.
    sleep_s = randint(4, 100)
    print(f"[*] Sleeping for {sleep_s}s...")
    sleep(sleep_s)

    # Seeds the RNG with the current Unix timestamp
    TARGET_SEED = time_ns() // 10**9
    prng = mt19937(TARGET_SEED)
    print(f"[*] Target seed is {TARGET_SEED}")

    # Waits a random number of seconds again.
    sleep_s = randint(4, 100)
    print(f"[*] Sleeping (again) for {sleep_s}s...")
    sleep(sleep_s)

    # Returns the first 32 bit output of the RNG.
    return next(prng)


@pytest.mark.skip(reason="Crack an MT19937 seed (time-based)")
def test():
    r = random_prng()
    seed = time_ns() // 10**9

    print(f"[x] Going back in time to find seed for {r}...")
    while (next(mt19937(seed)) != r and seed > 0):
        print(f"[*] Trying seed {seed}", end='\r')
        seed -= 1

    print()
    if (seed != 0):
        assert (seed == TARGET_SEED)
        print(f"[+] Found seed for {r}: {seed}")


if __name__ == "__main__":
    test()
