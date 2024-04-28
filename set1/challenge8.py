from collections import Counter
from typing import List, Tuple


def find_patterns(data: str, pattern_length: int = 16) -> List[Tuple[str, int]]:
    return [
        (pattern, count) for pattern, count in Counter(
            [data[i:i+pattern_length]
             for i in range(0, len(data), pattern_length)]
        ).items() if count > 1
    ]


def test():
    line_count = 1
    possible_ecb = (line_count, "")
    for line in open("./set1/challenge_8.txt"):
        line = line.strip()

        patterns = find_patterns(line)
        if patterns:
            print(patterns)
            possible_ecb = (line_count, line)

        line_count += 1

    # Found after running program successfully first
    assert (possible_ecb[0] == 133)
    assert (possible_ecb[1] == (
        "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f"
        "4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a"
        "6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
    ))


if __name__ == '__main__':
    test()
