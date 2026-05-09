
"""
Inspired from this paper's scheme 1 RSA impl
Kim, K., Jong, Y., & Song, Y. (2024). Decryption speed up of RSA by pre-calculation. In Proceedings of the 2023 International Conference on Mathematics, Intelligent Computing and Machine Learning (MICML '23) (pp. 11–16). Association for Computing Machinery. https://doi.org/10.1145/3638264.3638269


Also using this paper impl of rsa signature using garner's algo

Fouque, Pierre-Alain & Martinet, Gwenaëlle & Poupard, Guillaume. (2003). 
Attacking unbalanced RSA-CRT using SPA. 
Cryptographic Hardware and Embedded Systems - CHES 2003, 5th International Workshop. 2779. 
10.1007/978-3-540-45238-6_21. 

Also using this paper scheme b key generations

Sun, Hung-Min & Hinek, M & wu, mu-en. (2005). 
On the design of rebalanced RSA-CRT. 
"""

from utils import get_random_odd, is_prime, solve_for_prime_component


def generate_keys():
    """
    key_length : security parameter (modulus size)
    n_e: bit length of e
    n_d: target bit length for private exponents dp and dq
    """

    key_length = 2048
    n_e = 512
    n_d = 768

    e = get_random_odd(n_e)
    while not is_prime(e):
        e = get_random_odd(n_e)

    p, dp = solve_for_prime_component(e, key_length, n_e, n_d)

    while True:
        q, dq = solve_for_prime_component(e, key_length, n_e, n_d)
        if p != q:
            break

    n = p * q

    h = 2**(key_length // 4)

    q_inv = pow(q, -1, p)

    d0p = dp % h
    d0q = dq % h

    d1p = (dp - d0p) // h
    d1q = (dq - d0q) // h

    public_key = (e, h)
    private_key = (d0p, d0q, d1p, d1q, p, q, q_inv)

    protocol = "precalc"

    return public_key, private_key, n, protocol


def encrypt(pt : bytes, public_key : tuple, n : int):

    e, h = public_key

    pt = int.from_bytes(pt)

    ct = pow(pt, e, n)

    z = pow(ct, h, n)

    ct = (ct, z)

    byte_size = ((n.bit_length() + 7) // 8)
    return b"".join(i.to_bytes(byte_size) for i in ct)


def decrypt(encrypted : bytes, private_key :tuple, n : int):

    byte_size = ((n.bit_length() + 7) // 8)
    ct, z = (int.from_bytes(encrypted[i : i + byte_size]) for i in (0, byte_size))
    d0p, d0q, d1p, d1q, p, q, q_inv = private_key

    cp = ct % p
    cq = ct % q
    zp = z % p
    zq = z % q

    mp = (pow(cp, d0p, p) * pow(zp, d1p, p)) % p

    mq = (pow(cq, d0q, q) * pow(zq, d1q, q)) % q

    pt = (((mp - mq) * q_inv) % p) * q + mq # di konfrens papernya typo jadi mp, dibenerin jadi mq
    
    return pt.to_bytes(byte_size)