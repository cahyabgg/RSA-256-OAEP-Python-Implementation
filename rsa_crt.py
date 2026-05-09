

"""
Inspired from this paper's scheme 1 RSA impl
Kim, K., Jong, Y., & Song, Y. (2024). Decryption speed up of RSA by pre-calculation. In Proceedings of the 2023 International Conference on Mathematics, Intelligent Computing and Machine Learning (MICML '23) (pp. 11–16). Association for Computing Machinery. https://doi.org/10.1145/3638264.3638269

"""

from os import urandom

def get_random_int(N, randfunc = urandom):
    S = randfunc(N>>3)
    value = int.from_bytes(S)

    mask = (1 << N) - 1
    value &= mask
    value |= (1 << (N - 1))

    return value

def miller_rabin(a, q, n, k):
    progress = pow(a, q, n)

    if progress == 1 or progress == n - 1: return True
        
    for _ in range(k - 1):
        progress = pow(progress, 2, n)

        if progress == n - 1: return True
        
    return False


def is_prime(n, trials=5, randfunc=urandom):
    k = 0
    q = n - 1
    while q % 2 == 0:
        k += 1
        q //= 2

    for _ in range(trials):
        bit_size = n.bit_length()
        witness = get_random_int(bit_size, randfunc)
        witness = (witness % (n - 3)) + 2
        if not miller_rabin(witness, q, n, k):
            return False
        
    return True


def get_prime(N):
    randfunc = urandom

    if N < 2:
        raise ValueError("N must be larger than 1")

    while True:
        number = get_random_int(N, randfunc) | 1
        if is_prime(number, randfunc=randfunc):
            break
    return number

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
    
    return e, (d, p, q, dP, dQ, qInv), n

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def encrypt(m : bytes, e: int, n : int):
    m = int.from_bytes(m)
    byte_size = ((n.bit_length() + 7) // 8)
    return pow(m, e, n).to_bytes(byte_size)

def decrypt(c : bytes, key : tuple, n : int):
    d, p, q, dP, dQ, qInv = key

    c = int.from_bytes(c)

    m1 = pow(c, dP, p)
    m2 = pow(c, dQ, q)

    h = (qInv * (m1 - m2)) % p
    m = m2 + h * q

    byte_size = ((n.bit_length() + 7) // 8)
    return m.to_bytes(byte_size, 'big')