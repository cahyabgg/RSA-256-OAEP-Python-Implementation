
def file_chunk_iterator(filename, chunk_size=190):
    """Read a file in chunks. Default 190 bytes for OAEP with 2048-bit RSA."""
    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk
