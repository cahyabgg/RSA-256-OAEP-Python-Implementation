"""
Key file handler for RSA keys.
Saves and loads keys in hexadecimal text format.

Supports all three RSA protocols: textbook, crt, precalc.
"""


def _int_to_hex(n):
    """Convert integer to hex string (without '0x' prefix)."""
    if n == 0:
        return "0"
    # Handle negative numbers
    if n < 0:
        return "-" + hex(abs(n))[2:]
    return hex(n)[2:]


def _hex_to_int(h):
    """Convert hex string back to integer."""
    if h.startswith("-"):
        return -int(h[1:], 16)
    return int(h, 16)


def save_public_key(filepath, e, n, protocol):
    """
    Save public key to a hex text file.

    For precalc protocol, e is a tuple (e_val, h).
    For other protocols, e is an integer.
    """
    with open(filepath, "w") as f:
        f.write(f"protocol={protocol}\n")
        if protocol == "precalc":
            e_val, h = e
            f.write(f"e={_int_to_hex(e_val)}\n")
            f.write(f"h={_int_to_hex(h)}\n")
        else:
            f.write(f"e={_int_to_hex(e)}\n")
        f.write(f"n={_int_to_hex(n)}\n")


def save_private_key(filepath, d, n, protocol):
    """
    Save private key to a hex text file.

    For crt protocol, d is a tuple (p, q, dp, dq, q_inv).
    For precalc protocol, d is a tuple (d0p, d0q, d1p, d1q, p, q, q_inv).
    For textbook protocol, d is an integer.
    """
    with open(filepath, "w") as f:
        f.write(f"protocol={protocol}\n")
        if protocol == "crt":
            p, q, dp, dq, q_inv = d
            f.write(f"p={_int_to_hex(p)}\n")
            f.write(f"q={_int_to_hex(q)}\n")
            f.write(f"dp={_int_to_hex(dp)}\n")
            f.write(f"dq={_int_to_hex(dq)}\n")
            f.write(f"q_inv={_int_to_hex(q_inv)}\n")
        elif protocol == "precalc":
            d0p, d0q, d1p, d1q, p, q, q_inv = d
            f.write(f"d0p={_int_to_hex(d0p)}\n")
            f.write(f"d0q={_int_to_hex(d0q)}\n")
            f.write(f"d1p={_int_to_hex(d1p)}\n")
            f.write(f"d1q={_int_to_hex(d1q)}\n")
            f.write(f"p={_int_to_hex(p)}\n")
            f.write(f"q={_int_to_hex(q)}\n")
            f.write(f"q_inv={_int_to_hex(q_inv)}\n")
        else:
            # textbook
            f.write(f"d={_int_to_hex(d)}\n")
        f.write(f"n={_int_to_hex(n)}\n")


def load_public_key(filepath):
    """
    Load public key from a hex text file.

    Returns: (e, n, protocol)
    For precalc, e is a tuple (e_val, h).
    """
    data = {}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value

    protocol = data["protocol"]
    n = _hex_to_int(data["n"])

    if protocol == "precalc":
        e = (_hex_to_int(data["e"]), _hex_to_int(data["h"]))
    else:
        e = _hex_to_int(data["e"])

    return e, n, protocol


def load_private_key(filepath):
    """
    Load private key from a hex text file.

    Returns: (d, n, protocol)
    For crt, d is a tuple (p, q, dp, dq, q_inv).
    For precalc, d is a tuple (d0p, d0q, d1p, d1q, p, q, q_inv).
    For textbook, d is an integer.
    """
    data = {}
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value

    protocol = data["protocol"]
    n = _hex_to_int(data["n"])

    if protocol == "crt":
        d = (
            _hex_to_int(data["p"]),
            _hex_to_int(data["q"]),
            _hex_to_int(data["dp"]),
            _hex_to_int(data["dq"]),
            _hex_to_int(data["q_inv"]),
        )
    elif protocol == "precalc":
        d = (
            _hex_to_int(data["d0p"]),
            _hex_to_int(data["d0q"]),
            _hex_to_int(data["d1p"]),
            _hex_to_int(data["d1q"]),
            _hex_to_int(data["p"]),
            _hex_to_int(data["q"]),
            _hex_to_int(data["q_inv"]),
        )
    else:
        # textbook
        d = _hex_to_int(data["d"])

    return d, n, protocol
