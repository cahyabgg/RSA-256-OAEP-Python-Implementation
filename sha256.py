"""
SHA-256 implementation from scratch.
Reference: FIPS 180-4 (https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
"""

# Section 4.2.2: SHA-256 Constants
# First 32 bits of the fractional parts of the cube roots of the first 64 primes
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Section 5.3.3: Initial Hash Values
# First 32 bits of the fractional parts of the square roots of the first 8 primes
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

MASK32 = 0xFFFFFFFF


def _rotr(x, n):
    """Section 3.2: Rotate right (circular right shift)."""
    return ((x >> n) | (x << (32 - n))) & MASK32


def _shr(x, n):
    """Section 3.2: Right shift."""
    return x >> n


# Section 4.1.2: SHA-256 Functions

def _ch(x, y, z):
    return (x & y) ^ (~x & z) & MASK32


def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def _sigma0(x):
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _sigma1(x):
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _gamma0(x):
    return _rotr(x, 7) ^ _rotr(x, 18) ^ _shr(x, 3)


def _gamma1(x):
    return _rotr(x, 17) ^ _rotr(x, 19) ^ _shr(x, 10)


class SHA256:
    """SHA-256 hash object. API compatible with hashlib.sha256."""

    block_size = 64   # 512 bits
    digest_size = 32   # 256 bits

    def __init__(self, data=b""):
        self._h = list(H_INIT)
        self._buffer = b""
        self._length = 0  # total message length in bytes
        if data:
            self.update(data)

    def update(self, data: bytes):
        """Feed more data into the hash."""
        self._length += len(data)
        self._buffer += data

        # Process complete 512-bit (64-byte) blocks
        while len(self._buffer) >= 64:
            self._compress(self._buffer[:64])
            self._buffer = self._buffer[64:]

    def _compress(self, block: bytes):
        """Section 6.2.2: Process a single 512-bit block."""

        # 1. Prepare the message schedule W
        W = []
        for i in range(16):
            W.append(int.from_bytes(block[i * 4:(i + 1) * 4], "big"))
        for i in range(16, 64):
            W.append((_gamma1(W[i - 2]) + W[i - 7] + _gamma0(W[i - 15]) + W[i - 16]) & MASK32)

        # 2. Initialize working variables
        a, b, c, d, e, f, g, h = self._h

        # 3. 64 rounds of compression
        for i in range(64):
            T1 = (h + _sigma1(e) + _ch(e, f, g) + K[i] + W[i]) & MASK32
            T2 = (_sigma0(a) + _maj(a, b, c)) & MASK32
            h = g
            g = f
            f = e
            e = (d + T1) & MASK32
            d = c
            c = b
            b = a
            a = (T1 + T2) & MASK32

        # 4. Compute intermediate hash value
        self._h[0] = (self._h[0] + a) & MASK32
        self._h[1] = (self._h[1] + b) & MASK32
        self._h[2] = (self._h[2] + c) & MASK32
        self._h[3] = (self._h[3] + d) & MASK32
        self._h[4] = (self._h[4] + e) & MASK32
        self._h[5] = (self._h[5] + f) & MASK32
        self._h[6] = (self._h[6] + g) & MASK32
        self._h[7] = (self._h[7] + h) & MASK32

    def digest(self) -> bytes:
        """Section 5.1.1: Return the final hash as bytes."""
        # Work on a copy so digest() can be called multiple times
        h_copy = list(self._h)
        buf = self._buffer
        msg_len = self._length

        # Padding: append bit '1', then zeros, then 64-bit length
        buf += b"\x80"
        # Pad to 56 mod 64 bytes (448 mod 512 bits)
        while len(buf) % 64 != 56:
            buf += b"\x00"
        # Append original message length in bits as 64-bit big-endian
        buf += (msg_len * 8).to_bytes(8, "big")

        # Process remaining blocks
        for i in range(0, len(buf), 64):
            self._compress(buf[i:i + 64])

        result = b"".join(word.to_bytes(4, "big") for word in self._h)

        # Restore state
        self._h = h_copy
        return result

    def hexdigest(self) -> str:
        """Return the final hash as a hex string."""
        return self.digest().hex()

    def copy(self):
        """Return a copy of the hash object."""
        clone = SHA256()
        clone._h = list(self._h)
        clone._buffer = self._buffer
        clone._length = self._length
        return clone


def sha256(data: bytes = b"") -> SHA256:
    """Convenience function, drop-in replacement for hashlib.sha256."""
    return SHA256(data)
