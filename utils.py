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

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a