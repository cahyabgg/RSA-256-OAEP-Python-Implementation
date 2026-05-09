

"""
Inspired from this paper's scheme 1 RSA impl
Kim, K., Jong, Y., & Song, Y. (2024). Decryption speed up of RSA by pre-calculation. In Proceedings of the 2023 International Conference on Mathematics, Intelligent Computing and Machine Learning (MICML '23) (pp. 11–16). Association for Computing Machinery. https://doi.org/10.1145/3638264.3638269

"""

from utils import get_prime, is_prime, gcd

# RSA Key Generation
def generate_keys():
    
    p = get_prime(1024)
    q = get_prime(1024)
    
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while True:
        if gcd(e, phi) == 1 and is_prime(e):
            break
        e += 2

    d = pow(e, -1, phi)


    dP = d % (p - 1)
    dQ = d % (q - 1)
    qInv = pow(q, -1, p)

    d = (p, q, dP, dQ, qInv)
    
    return e, d, n

def encrypt(pt : bytes, e: int, n : int):
    pt = int.from_bytes(pt)
    byte_size = ((n.bit_length() + 7) // 8)
    return pow(pt, e, n).to_bytes(byte_size)

def decrypt(ct : bytes, d : tuple, n : int):
    p, q, dP, dQ, qInv = d

    ct = int.from_bytes(ct)

    m1 = pow(ct, dP, p)
    m2 = pow(ct, dQ, q)

    h = (qInv * (m1 - m2)) % p
    m = m2 + h * q

    byte_size = ((n.bit_length() + 7) // 8)
    return m.to_bytes(byte_size, 'big')