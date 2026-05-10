from rsa_crt import encrypt,decrypt, generate_keys
from oaep import oaep_encode, oaep_decode
from file_handler import file_chunk_iterator, write_metadata, read_metadata

e, d, n, protocol = generate_keys()

def file_encrypt(filename):

    filename_out = filename[:filename.find(".")] + ".rsa"

    write_metadata(filename, filename_out)

    file_iterator = file_chunk_iterator(filename)
    with open(filename_out, "ab") as out:
        for chunk in file_iterator:
            encoded_chunk = oaep_encode(filename, n, chunk)
            encrypted_encoded_chunk = encrypt(encoded_chunk,e,n)
            out.write(encrypted_encoded_chunk)

def file_decrypt(filename):

    label_length, original_label = read_metadata(filename)
    
    chunk_size = 0
    if protocol == "precalc":
        chunk_size = 512
    else:
        chunk_size = 256

    file_iterator = file_chunk_iterator(filename,chunk_size, label_length)

    with open(original_label, "wb") as out:
        for chunk in file_iterator:
            decrypted_encoded_chunk = decrypt(chunk,d,n)
            decoded_chunk = oaep_decode(original_label, n, decrypted_encoded_chunk)
            out.write(decoded_chunk)

if __name__ == "__main__":
    filename = r"rec_0923.wav"
    filename_out = filename[:filename.find(".")] + ".rsa"

    file_encrypt(filename)
    file_decrypt(filename_out)