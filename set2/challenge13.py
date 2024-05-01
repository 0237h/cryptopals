import json
from typing import Dict
from urllib.parse import parse_qsl, urlencode
from uuid import uuid4
from challenge11 import random_128

import sys
from os import path

sys.path.insert(1, path.abspath("set1"))  # Python hack to resolve set1/ challenges imports

from challenge7 import __print_block, decrypt_aes128_ecb, encrypt_aes128_ecb  # noqa # type: ignore


def parse_kv(kv_string: str) -> Dict:
    return dict(parse_qsl(kv_string))


def profile_for(email: str) -> str:
    assert (len(email) > 0)

    return urlencode({
        "email": email,
        "uid": uuid4(),
        "role": "user"
    })


def test_parse_kv():
    assert (
        parse_kv("foo=bar&baz=qux&zap=zazzle") == {
            "foo": 'bar',
            "baz": 'qux',
            "zap": 'zazzle'
        }
    )


def test_profile_for():
    assert (
        "email=foo%40bar.com" in profile_for("foo@bar.com")
    )

    assert (
        "email=foo%40bar.com%26role%3Dadmin" in profile_for("foo@bar.com&role=admin") and
        "role=user" in profile_for("foo@bar.com&role=admin")
    )


def encrypt_user_profile(email: str, key: bytes) -> bytes:
    return encrypt_aes128_ecb(profile_for(email).encode(), key)


def decrypt_user_profile(ciphertext: bytes, key: bytes) -> Dict:
    return parse_kv(decrypt_aes128_ecb(ciphertext, key).decode())


def test():
    user = "foo@bar.com"
    key = random_128()
    ciphertext = encrypt_user_profile(user, key)

    print(f"[+] Encrypted user profile with random key for user '{user}'")
    __print_block(ciphertext)

    decrypted_user_profile = decrypt_user_profile(ciphertext, key)
    print(f"[+] Decrypted user profile for user '{user}':")
    print(json.dumps(decrypted_user_profile, indent=4))

    # Visualizing the ECB "cut-and-paste"
    # -----------------------------------
    #
    # Here is what the minimal input plaintext string looks like:
    # email=?&uid=202f40f4-85d0-4dfa-b9a1-b2c1ba0d7cf0&role=user
    # ---------------|---------------|---------------|---------------|
    #     Block #1        Block #2        Block #3        Block #4
    #
    # We can make the `user` portion we want to replace into its own encrypted block by providing input of right length:
    # email=aaaaaaaaaaa&uid=202f40f4-85d0-4dfa-b9a1-b2c1ba0d7cf0&role=user
    # ---------------|---------------|---------------|---------------|---------------|
    #                                                                 ^ New block
    #
    # To generate the right encrypted block for the `admin` text, we use the same padding technique:
    # email=aaaaaaaaaaadmin&uid=202f40f4-85d0-4dfa-b9a1-b2c1ba0d7cf0&role=user
    # ---------------|---------------|---------------|---------------|---------------|
    #                 ^ Cut this block
    #
    # Notice we also have random junk after `admin` that will also get parsed at the end.
    # The `urlencode` implementation used here for the parsing won't let us pad nicely and escape any byte sequence we
    # might want to use. So to make the rest of `admin` block characters disappear, we have to create a padding value
    # that will truncate all characters until our `admin` text.
    #
    # To do that, we have to use a value that will not be URL-encoded so only letters (both cases) and numbers. We can
    # figure out the padding character by solving this formula: c = 16*n + 11
    #
    # The first n value that gives a character within the [A-z0-9] range is our padding character ! Turns out 'F' works
    # for a value of n = 4. That means we'll need to past 4 blocks of 'F' (only last byte really needs to be 'F') for
    # the truncation to remove 75 characters (ASCII value of 'F') which will do the trick to remove the junk characters.
    # email=aaaaaaaaaaFFFFFFFFFFFFFFFF&uid=202f40f4-85d0-4dfa-b9a1-b2c1ba0d7cf0&role=user
    # ---------------|---------------|---------------|---------------|---------------|
    #                 ^ Cut this block
    #
    # In the end we paste our cutted block with `admin` over the last original block of the cipher and append our
    # padding blocks. So the result is decoded to this:
    # email=uarepwned..&uid=202f40f4-85d0-4dfa-b9a1-b2c1ba0d7cf0&role=admin&uid=202f40 ['F' PADDING]   ['F' PADDING]   ['F' PADDING]   ['F' PADDING] # noqa
    # ---------------|---------------|---------------|---------------|---------------|---------------|---------------|---------------|---------------|
    #                                                                 ^ Pasted block
    #                                                                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #                                                                      Truncated from PKCS#7
    # Which gives us `admin` role for any email !

    forged_ciphertext = encrypt_user_profile("aaaaaaaaaa" + "admin", key)[16:32]
    print(f"[*] Cut `admin` block")
    __print_block(forged_ciphertext)

    # We could also extract all intermediate ciphertext in one call to `encrypt_user_profile`
    padding_ciphertext = encrypt_user_profile("aaaaaaaaaa" + "F" * 16, key)[16:32] * 4
    print(f"[*] Create padding block")
    __print_block(padding_ciphertext)

    make_admin_ciphertext = encrypt_user_profile("uarepwned..", key)[:-16] + forged_ciphertext + padding_ciphertext
    print(f"[*] Pasting and appending to forged block")
    __print_block(make_admin_ciphertext)

    admin_profile = decrypt_user_profile(make_admin_ciphertext, key)
    assert (admin_profile["role"] == "admin")

    print(f"[+] Decrypted `admin` profile:")
    print(json.dumps(admin_profile, indent=4))


if __name__ == "__main__":
    test()
