from hashlib import sha256
from os import urandom

def mgf1(seed: bytes, length: int, hash_func=sha256) -> bytes:
    """Mask generation function."""
    hLen = hash_func().digest_size
    # https://www.ietf.org/rfc/rfc2437.txt
    # 1. If l > 2^32(hLen), output "mask too long" and stop.
    if length > (hLen << 32):
        raise ValueError("mask too long")
    # 2. Let T be the empty octet string.
    T = b""
    # 3. For counter from 0 to \lceil{l / hLen}\rceil-1, do the following:
    # Note: \lceil{l / hLen}\rceil-1 is the number of iterations needed,
    #       but it's easier to check if we have reached the desired length.
    counter = 0
    while len(T) < length:
        # a. Convert counter to an octet string C of length 4 with the primitive I2OSP: C = I2OSP (counter, 4)
        C = int.to_bytes(counter, 4, "big")
        # b. Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash (Z || C)
        T += hash_func(seed + C).digest()
        counter += 1
    # 4. Output the leading l octets of T as the octet string mask.
    return T[:length]

def oaep_encode(l : str, k : int, m : bytes) :
    l = l.encode()
    l_hash = sha256(l).digest()
    h_len = len(l_hash)

    k = (k.bit_length() + 7) // 8
    m_len = len(m)
    ps_len = k - m_len - 2 * h_len - 2
    ps = b"\x00" * ps_len
    db = l_hash + ps + b"\x01" + m

    seed = urandom(h_len)

    db_mask = mgf1(seed, k- h_len - 1)

    masked_db = (int.from_bytes(db) ^ int.from_bytes(db_mask)).to_bytes(len(db))

    seed_mask = mgf1(masked_db, h_len)

    masked_seed = (int.from_bytes(seed) ^ int.from_bytes(seed_mask)).to_bytes(len(seed))

    return b"\x00" + masked_seed + masked_db

def oaep_decode(l : str,k : int,encoded : bytes):
    l = l.encode()
    l_hash = sha256(l).digest()
    h_len = len(l_hash)

    if encoded[0] != 0x00:
        raise ValueError("Decoding error: Invalid leading byte.")

    masked_seed = encoded[1 : 1 + h_len]
    masked_db = encoded[1 + h_len :]

    seed_mask = mgf1(masked_db, h_len)

    seed = (int.from_bytes(masked_seed) ^ int.from_bytes(seed_mask)).to_bytes(len(masked_seed))

    k = (k.bit_length() + 7) // 8

    db_mask = mgf1(seed, k - h_len - 1)

    db = (int.from_bytes(db_mask) ^ int.from_bytes(masked_db)).to_bytes(len(db_mask))

    lhash_prime = db[:h_len]
    if lhash_prime != l_hash:
        raise ValueError("Decoding error: lHash mismatch.")

    separator_index = -1

    for i in range(h_len, len(db)):
        if db[i] == 0x01:
            separator_index = i
            break
        elif db[i] != 0x00:
            raise ValueError("Decoding error: Invalid byte in padding string.")

    if separator_index == -1:
        raise ValueError("Decoding error: Separator byte 0x01 not found.")

    return db[separator_index + 1:]