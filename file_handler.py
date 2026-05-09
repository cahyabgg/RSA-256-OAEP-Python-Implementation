
def file_chunk_iterator(filename, chunk_size=190):
    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            yield chunk