
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

    return e, d, n

def encrypt(pt : bytes, e: int, n : int):
    pt = int.from_bytes(pt)
    byte_size = ((n.bit_length() + 7) // 8)
    return pow(pt, e, n).to_bytes(byte_size)

def decrypt(ct : bytes, d : int, n : int):
    ct = int.from_bytes(ct)
    byte_size = ((n.bit_length() + 7) // 8)
    return pow(ct, d, n).to_bytes(byte_size)