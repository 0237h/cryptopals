from typing import Optional
from challenge39 import i2osp, invmod, os2ip, rsa

# Precompute valid RSA keys for speed
USE_PRECOMPUTED_RSA_KEYS = True
# P,Q values for RSA keys
PQS = (
    (
        60773218950612049045122753090147126778242239946894951708579230816426579907720921102220863386343945107054052668646853773224882454485343973040932143185002385385879237425526192280381535677512327995058726316278277412791221886087808485014196872363607169709220739260140302364607879914407321001828121727983370239031,
        35969320346296449807206991910311481273010597254967765760480269787095774156302237157845839194836517627233176724903254659733966461912186357151585665333855714960073700494680641476805365074773421069070618877376043305690572899476052053948794169223844578423360422742871383079587495792565239485941206790414020045953
    ),
    (
        36571443300971471865927726232265757081773890508346511767205098973419200030243928959640361944823069518169063110670426370104986207839977096356584627955968827735721770956635838213814241246469743664343273308181045563703580237314482041876806908736422470634182478691288913597622197730876939552354738267322905180467,
        76878923901442023782012939375834833184731678919480581938331332983644763795902497066933740556838773876578901436041164671697275824377813711978855553358814282530693998631022408454346096251839996640516710531829010389091918134496550309445560191136573172794655076347901997424195809252284953610530753546385398848879
    ),
    (
        82896818850167949405118098914530440416366355442320171106021879103483767299200032526535131883578072762485213126634207485768001672734824661379944848909754734844540059700759628150484661730324792134652029017873111412248327964218475559600030187588275026069325258812310716732816932655726806987490847272269938660111,
        163640014981801337610718764383425915917480352684930218969880451175896828754898130578144789966320887920718639145967167643527461495515684388452484467694076637380431113056568589501561370436915576261243635969215635419836116809832910300357952391694891697316005656168453488409197600558954298731386314860212324457829
    )
)


def find_invpow(x, n):
    """Finds the integer component of the n'th root of x,
    an integer such that y ** n <= x < (y + 1) ** n.

    Adapted from https://stackoverflow.com/a/356206
    """
    high = 1
    while high ** n <= x:
        high *= 2
    low = high//2
    mid = 0
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1


class User:
    def __init__(self, name: str, pq: Optional[tuple[int, int]] = None) -> None:
        self.name = name
        self.key_length, self.pub_key, self.priv_key, self.enc, self.dec = rsa(e=3, pq=pq)
        print(f"[*] [{self.name}] Key length: {self.key_length}")
        print(f"[*] [{self.name}] Public key: {self.pub_key}")

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.enc(plaintext, use_padding=False)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.dec(ciphertext, use_padding=False)


def test():
    print(f"[x] Generating RSA keys...")
    alice = User('Alice', PQS[0] if USE_PRECOMPUTED_RSA_KEYS else None)
    bob = User('Bob', PQS[1] if USE_PRECOMPUTED_RSA_KEYS else None)
    charlie = User('Charlie', PQS[2] if USE_PRECOMPUTED_RSA_KEYS else None)

    message = b"YELLOW SUBMARINE"*15
    ciphertexts = (alice.encrypt(message), bob.encrypt(message), charlie.encrypt(message))
    print(f"[*] Ciphertexts: {[c.hex() for c in ciphertexts]}")

    assert alice.decrypt(ciphertexts[0]) == bob.decrypt(ciphertexts[1]) == charlie.decrypt(ciphertexts[2]) == message

    n_0, n_1, n_2 = alice.pub_key[1], bob.pub_key[1], charlie.pub_key[1]
    c_0, c_1, c_2 = os2ip(ciphertexts[0]) % n_0, os2ip(ciphertexts[1]) % n_1, os2ip(ciphertexts[2]) % n_2
    m_s_0, m_s_1, m_s_2 = n_1 * n_2, n_0 * n_2, n_0 * n_1
    result = (c_0 * m_s_0 * invmod(m_s_0, n_0)
              + c_1 * m_s_1 * invmod(m_s_1, n_1)
              + c_2 * m_s_2 * invmod(m_s_2, n_2)) % (n_0 * n_1 * n_2)
    root = find_invpow(result, 3)

    print(f"[+] Found cubic root:\n{root}")
    print(f"[+] Decrypted message:\n{i2osp(root, len(message))}")


if __name__ == "__main__":
    test()
