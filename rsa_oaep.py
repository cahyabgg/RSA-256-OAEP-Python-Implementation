from oaep import oaep_encode, oaep_decode
from file_handler import file_chunk_iterator
from key_handler import save_public_key, save_private_key, load_public_key, load_private_key

# Default OAEP label (empty string per standard)
OAEP_LABEL = ""


def generate_and_save_keys(public_key_path, private_key_path, protocol="crt"):
    """Generate RSA key pair and save to hex files."""
    if protocol == "crt":
        from rsa_crt import generate_keys
    elif protocol == "precalc":
        from rsa_precalc import generate_keys
    else:
        from rsa_textbook import generate_keys

    e, d, n, protocol = generate_keys()
    save_public_key(public_key_path, e, n, protocol)
    save_private_key(private_key_path, d, n, protocol)
    return e, d, n, protocol


def _get_encrypt_func(protocol):
    if protocol == "crt":
        from rsa_crt import encrypt
    elif protocol == "precalc":
        from rsa_precalc import encrypt
    else:
        from rsa_textbook import encrypt
    return encrypt


def _get_decrypt_func(protocol):
    if protocol == "crt":
        from rsa_crt import decrypt
    elif protocol == "precalc":
        from rsa_precalc import decrypt
    else:
        from rsa_textbook import decrypt
    return decrypt


def file_encrypt(plaintext_file, public_key_file, output_file):
    """
    Encrypt a file using RSA-OAEP-256.

    Args:
        plaintext_file: path to the file to encrypt (any binary file)
        public_key_file: path to the public key file (hex format)
        output_file: path to write the ciphertext
    """
    e, n, protocol = load_public_key(public_key_file)
    encrypt = _get_encrypt_func(protocol)

    file_iterator = file_chunk_iterator(plaintext_file)
    with open(output_file, "wb") as out:
        for chunk in file_iterator:
            encoded_chunk = oaep_encode(OAEP_LABEL, n, chunk)
            encrypted_encoded_chunk = encrypt(encoded_chunk, e, n)
            out.write(encrypted_encoded_chunk)


def file_decrypt(ciphertext_file, private_key_file, output_file):
    """
    Decrypt a file using RSA-OAEP-256.

    Args:
        ciphertext_file: path to the encrypted file
        private_key_file: path to the private key file (hex format)
        output_file: path to write the decrypted plaintext
    """
    d, n, protocol = load_private_key(private_key_file)
    decrypt = _get_decrypt_func(protocol)

    chunk_size = 512 if protocol == "precalc" else 256

    file_iterator = file_chunk_iterator(ciphertext_file, chunk_size)

    with open(output_file, "wb") as out:
        for chunk in file_iterator:
            decrypted_encoded_chunk = decrypt(chunk, d, n)
            decoded_chunk = oaep_decode(OAEP_LABEL, n, decrypted_encoded_chunk)
            out.write(decoded_chunk)