def bencode(data):
    """
    Encode Python objects into bencoded bytes.
    """
    if isinstance(data, str):
        # Convert Python str to bytes and then encode as bencoded byte string
        return f"{len(data)}:{data}".encode()
    elif isinstance(data, bytes):
        # Directly encode bytes to bencoded byte string
        return f"{len(data)}:".encode() + data
    elif isinstance(data, int):
        # Encode Python integers to bencoded integers
        return f"i{data}e".encode()
    elif isinstance(data, list):
        # Recursively bencode each item in the list
        encoded_list = b"l" + b"".join(bencode(item) for item in data) + b"e"
        return encoded_list
    elif isinstance(data, dict):
        # Encode dictionaries, ensuring keys are sorted as raw strings
        encoded_dict = b"d"
        # Sort keys and ensure they are byte strings, encode values recursively
        for key, value in sorted(data.items(), key=lambda item: item[0]):
            encoded_key = bencode(str(key))
            encoded_value = bencode(value)
            encoded_dict += encoded_key + encoded_value
        encoded_dict += b"e"
        return encoded_dict
    else:
        raise TypeError(f"Type {type(data)} not supported by bencode.")

def bdecode(data):
    """
    Decode bencoded bytes back into Python objects.
    Handles byte strings as raw bytes to avoid decoding errors.
    """
    def decode_next(data, index):
        start_char = chr(data[index])
        
        if start_char.isdigit():
            colon_index = data.index(b':', index)
            length = int(data[index:colon_index])
            start = colon_index + 1
            end = start + length
            # Only decode as string if it's safe to assume it's not binary data
            segment = data[start:end]
            if all(32 <= byte < 127 for byte in segment):  # Rough check for text-safety
                return segment.decode(), end
            return segment, end  # Return as bytes if potentially binary
        
        elif start_char == 'i':
            end_index = data.index(b'e', index)
            num = int(data[index + 1:end_index])
            return num, end_index + 1
        
        elif start_char == 'l':
            index += 1
            lst = []
            while data[index] != ord('e'):
                item, index = decode_next(data, index)
                lst.append(item)
            return lst, index + 1
        
        elif start_char == 'd':
            index += 1
            dic = {}
            while data[index] != ord('e'):
                key, index = decode_next(data, index)
                value, index = decode_next(data, index)
                dic[key] = value
            return dic, index + 1
        
        else:
            raise ValueError("Invalid bencoded value")
    
    result, _ = decode_next(data, 0)
    return result
