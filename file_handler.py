
def file_chunk_iterator(filename, chunk_size=190, skip_size=0):
    with open(filename, 'rb') as f:
        f.read(skip_size)
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            
            yield chunk

def write_metadata(filename_in, filename_out):

    label_bytes = filename_in.encode('utf-8')
    label_length = len(label_bytes)
    with open(filename_out, 'wb') as f:
        f.write(label_length.to_bytes(1))
        f.write(label_bytes)



        

def read_metadata(filename):
    label_length = 0
    original_label = ""

    with open(filename, 'rb') as f:
        label_length = int.from_bytes(f.read(1), 'big')
        original_label = f.read(label_length).decode('utf-8')



    return label_length + 1, original_label
