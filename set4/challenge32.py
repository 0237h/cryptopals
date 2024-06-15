import pytest
import challenge31

challenge31.SLEEP_TIME_MS = 1


@pytest.mark.skip(reason="Break HMAC-SHA1 with a slightly less artificial timing leak (1 ms)")
def test():
    challenge31.break_app_hmac(app_compare_resolution_ns=999664, averaging_count=9)


if __name__ == "__main__":
    test()
