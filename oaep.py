from sha256 import sha256
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
    # 3. For counter from 0 to ceil( l / hlen) - 1
    # it's easier to check if we have reached the desired length.
    counter = 0
    while len(T) < length:
        # a. Convert counter to an octet string C of length 4 with the primitive I2OSP: C = I2OSP (counter, 4)
        C = int.to_bytes(counter, 4, "big")
        # b. Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash (Z || C)
        T += hash_func(seed + C).digest()
        counter += 1
    # 4. Output the leading l octets of T as the octet string mask.
    return T[:length]

def oaep_encode(l : str, k : int, m : bytes)  -> bytes:

    # https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
    # 1. Hash the label L using the chosen hash function: lHash = Hash(L)
    l = l.encode()
    l_hash = sha256(l).digest()
    h_len = len(l_hash)

    # 2. Generate a padding string PS consisting 
    # of k - mLen - 2 * hLen - 2 bytes (0x00 and 0x01).
    m_len = len(m)
    ps_len = k - m_len - 2 * h_len - 2
    ps = b"\x00" * ps_len

    # 3. Concatenate lHash, PS, the single byte 0x01, 
    # and the message M to form a data block DB: DB = lHash || PS || 0x01 || M. 
    # This data block has length k - hLen - 1 bytes.
    db = l_hash + ps + b"\x01" + m

    # 4. Generate a random seed of length hLen.
    seed = urandom(h_len)

    # 5. Use the mask generating function to 
    # generate a mask of the appropriate length for the data block: 
    # dbMask = MGF(seed, k - hLen - 1)
    db_mask = mgf1(seed, k- h_len - 1)

    # 6. Mask the data block with the generated mask: maskedDB = DB ^ dbMask
    masked_db = (int.from_bytes(db) ^ int.from_bytes(db_mask)).to_bytes(len(db))

    # 7. Use the mask generating function to 
    # generate a mask of length hLen for the seed: 
    # seedMask = MGF(maskedDB, hLen)
    seed_mask = mgf1(masked_db, h_len)

    # 8. Mask the seed with the generated mask: 
    # maskedSeed = seed ^ seedMask
    masked_seed = (int.from_bytes(seed) ^ int.from_bytes(seed_mask)).to_bytes(len(seed))

    # 9. The encoded (padded) message is the byte 0x00 
    # concatenated with the maskedSeed and maskedDB: 
    # EM = 0x00 || maskedSeed || maskedDB
    return b"\x00" + masked_seed + masked_db

def oaep_decode(l : str, k : int, encoded : bytes) -> bytes:

    # https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
    # 1. Hash the label L using the chosen hash function: lHash = Hash(L)
    l = l.encode()
    l_hash = sha256(l).digest()
    h_len = len(l_hash)

    # 2. To reverse step 9, split the encoded message EM into the byte 0x00, 
    # the maskedSeed (with length hLen) and the maskedDB
    if encoded[0] != 0x00:
        raise ValueError("Decoding error: Invalid leading byte.")

    masked_seed = encoded[1 : 1 + h_len]
    masked_db = encoded[1 + h_len :]

    # 3. Generate the seedMask which was used to mask the seed: 
    # seedMask = MGF(maskedDB, hLen)
    seed_mask = mgf1(masked_db, h_len)

    # 4. To reverse step 8, recover the seed with the seedMask: 
    # seed = maskedSeed ^ seedMask
    seed = (int.from_bytes(masked_seed) ^ int.from_bytes(seed_mask)).to_bytes(len(masked_seed))


    # 5. Generate the dbMask which was used to mask the data block: 
    # dbMask = MGF(seed, k - hLen - 1)
    db_mask = mgf1(seed, k - h_len - 1)

    # 6. To reverse step 6, recover the data block DB: 
    # DB = maskedDB ^ dbMask
    db = (int.from_bytes(db_mask) ^ int.from_bytes(masked_db)).to_bytes(len(db_mask))

    # 7. To reverse step 3, split the data block into its parts: 
    # DB = lHash' || PS || 0x01 || M
    # 7.1 Verify that lHash' is equal to the computed lHash
    lhash_prime = db[:h_len]
    if lhash_prime != l_hash:
        raise ValueError("Decoding error: lHash mismatch.")

    separator_index = -1

    # 7.1 Verify that PS only consists of 
    # bytes 0x00 and PS and M are separated by 0x01
    for i in range(h_len, len(db)):
        if db[i] == 0x01:
            separator_index = i
            break
        elif db[i] != 0x00:
            raise ValueError("Decoding error: Invalid byte in padding string.")

    if separator_index == -1:
        raise ValueError("Decoding error: Separator byte 0x01 not found.")

    return db[separator_index + 1:]