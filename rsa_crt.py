
from utils import get_random_odd, is_prime, solve_for_prime_component

"""
Inspired by this paper impl of rsa signature using garner's algo

Fouque, Pierre-Alain & Martinet, Gwenaëlle & Poupard, Guillaume. (2003). 
Attacking unbalanced RSA-CRT using SPA. 
Cryptographic Hardware and Embedded Systems - CHES 2003, 5th International Workshop. 2779. 
10.1007/978-3-540-45238-6_21. 

Also using this paper scheme b key generations

Sun, Hung-Min & Hinek, M & wu, mu-en. (2005). 
On the design of rebalanced RSA-CRT. 
"""

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
    q_inv = pow(q, -1, p)

    d = (p, q, dp, dq, q_inv)

    protocol = "crt"

    return e, d, n, protocol

def encrypt(pt : bytes, e: int, n : int):
    pt = int.from_bytes(pt)
    byte_size = ((n.bit_length() + 7) // 8)
    return pow(pt, e, n).to_bytes(byte_size)

def decrypt(ct : bytes, d : tuple, n : int):
    p, q, dp, dq, q_inv = d

    ct = int.from_bytes(ct)

    m1 = pow(ct, dp, p)
    m2 = pow(ct, dq, q)

    h = (q_inv * (m1 - m2)) % p
    m = m2 + h * q

    byte_size = ((n.bit_length() + 7) // 8)
    return m.to_bytes(byte_size)