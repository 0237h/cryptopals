# cryptopals

Solving [cryptopals](https://cryptopals.com) challenges (in Python) ! Limiting myself to only use modules from the [standard library](https://docs.python.org/3.11/). 

**Environment**
```console
(.venv) cryptopals$ python --version
Python 3.11.2
```

**To validate challenges**
```console
(.venv) cryptopals$ pytest */*.py
```
Use `-vv` and `-s` for more output.

**To run a particular challenge**
```console
(.venv) cryptopals$ python set1/challenge1.py
```

## Progress

> Progress: 18/66 (27.27 %) completed (last completed, Challenge 18)

### Set 1

- [x] **Challenge 1** *Convert hex to base64*
- [x] **Challenge 2** *Fixed XOR*
- [x] **Challenge 3** *Single-byte XOR cipher*
- [x] **Challenge 4** *Detect single-character XOR*
- [x] **Challenge 5** *Implement repeating-key XOR*
- [x] **Challenge 6** *Break repeating-key XOR*
- [x] **Challenge 7** *AES in ECB mode*
- [x] **Challenge 8** *Detect AES in ECB mode*

### Set 2

- [x] **Challenge 9** *Implement PKCS#7 padding*
- [x] **Challenge 10** *Implement CBC mode*
- [x] **Challenge 11** *An ECB/CBC detection oracle*
- [x] **Challenge 12** *Byte-at-a-time ECB decryption (Simple)*
- [x] **Challenge 13** *ECB cut-and-paste*
- [x] **Challenge 14** *Byte-at-a-time ECB decryption (Harder)*
- [x] **Challenge 15** *PKCS#7 padding validation*
- [x] **Challenge 16** *CBC bitflipping attacks*

### Set 3

- [x] **Challenge 17** *The CBC padding oracle
- [x] **Challenge 18** *Implement CTR, the stream cipher mode*
- [ ] **Challenge 19** *Break fixed-nonce CTR mode using substitutions*
- [ ] **Challenge 20** *Break fixed-nonce CTR statistically*
- [ ] **Challenge 21** *Implement the MT19937 Mersenne Twister RNG*
- [ ] **Challenge 22** *Crack an MT19937 seed*
- [ ] **Challenge 23** *Clone an MT19937 RNG from its output*
- [ ] **Challenge 24** *Create the MT19937 stream cipher and break it*

### Set 4

- [ ] **Challenge 25** *Break "random access read/write" AES CTR*
- [ ] **Challenge 26** *CTR bitflipping*
- [ ] **Challenge 27** *Recover the key from CBC with IV=Key*
- [ ] **Challenge 28** *Implement a SHA-1 keyed MAC*
- [ ] **Challenge 29** *Break a SHA-1 keyed MAC using length extension*
- [ ] **Challenge 30** *Break an MD4 keyed MAC using length extension*
- [ ] **Challenge 31** *Implement and break HMAC-SHA1 with an artificial timing leak*
- [ ] **Challenge 32** *Break HMAC-SHA1 with a slightly less artificial timing leak*

### Set 5

- [ ] **Challenge 33** *Implement Diffie-Hellman*
- [ ] **Challenge 34** *Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection*
- [ ] **Challenge 35** *Implement DH with negotiated groups, and break with malicious "g" parameters*
- [ ] **Challenge 36** *Implement Secure Remote Password (SRP)*
- [ ] **Challenge 37** *Break SRP with a zero key*
- [ ] **Challenge 38** *Offline dictionary attack on simplified SRP*
- [ ] **Challenge 39** *Implement RSA*
- [ ] **Challenge 40** *Implement an E=3 RSA Broadcast attack*

### Set 6

- [ ] **Challenge 41** *Implement unpadded message recovery oracle*
- [ ] **Challenge 42** *Bleichenbacher's e=3 RSA Attack*
- [ ] **Challenge 43** *DSA key recovery from nonce*
- [ ] **Challenge 44** *DSA nonce recovery from repeated nonce*
- [ ] **Challenge 45** *DSA parameter tampering*
- [ ] **Challenge 46** *RSA parity oracle*
- [ ] **Challenge 47** *Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)*
- [ ] **Challenge 48** *Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)*

### Set 7

- [ ] **Challenge 49** *CBC-MAC Message Forgery*
- [ ] **Challenge 50** *Hashing with CBC-MAC*
- [ ] **Challenge 51** *Compression Ratio Side-Channel Attacks*
- [ ] **Challenge 52** *Iterated Hash Function Multicollisions*
- [ ] **Challenge 53** *Kelsey and Schneier's Expandable Messages*
- [ ] **Challenge 54** *Kelsey and Kohno's Nostradamus Attack*
- [ ] **Challenge 55** *MD4 Collisions*
- [ ] **Challenge 56** *RC4 Single-Byte Biases*

### Set 8

- [ ] **Challenge 57** *Diffie-Hellman Revisited: Small Subgroup Confinement*
- [ ] **Challenge 58** *Pollard's Method for Catching Kangaroos*
- [ ] **Challenge 59** *Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks*
- [ ] **Challenge 60** *Single-Coordinate Ladders and Insecure Twists*
- [ ] **Challenge 61** *Duplicate-Signature Key Selection in ECDSA (and RSA)*
- [ ] **Challenge 62** *Key-Recovery Attacks on ECDSA with Biased Nonces*
- [ ] **Challenge 63** *Key-Recovery Attacks on GCM with Repeated Nonces*
- [ ] **Challenge 64** *Key-Recovery Attacks on GCM with a Truncated MAC*
- [ ] **Challenge 65** *Truncated-MAC GCM Revisited: Improving the Key-Recovery Attack via Ciphertext Length Extension*
- [ ] **Challenge 66** *Exploiting Implementation Errors in Diffie-Hellman*
