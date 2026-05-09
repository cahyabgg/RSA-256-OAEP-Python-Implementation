from rsa_crt import encrypt,decrypt, generate_keys
from oaep import oaep_encode, oaep_decode
from file_handler import file_chunk_iterator

label = r"rec_0923.wav"

e, d, n = generate_keys()

file_iterator = file_chunk_iterator(label)
label_out = label[:label.find(".") - 1] + ".rsa"
with open(label_out, "wb") as out:
    for chunk in file_iterator:
        encoded_chunk = oaep_encode(label, n, chunk)
        encrypted_encoded_chunk = encrypt(encoded_chunk,e,n)
        out.write(encrypted_encoded_chunk)

file_iterator = file_chunk_iterator(label_out,256)
with open(label, "wb") as out:
    for chunk in file_iterator:
        decrypted_encoded_chunk = decrypt(chunk,d,n)
        decoded_chunk = oaep_decode(label, n, decrypted_encoded_chunk)
        out.write(decoded_chunk)