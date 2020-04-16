def hex_to_int(data):
    b = bytearray(data)
    return bytes_to_int(data)


def bytes_to_hex(data):
    hex_list = []
    for x in data:
        hex_list.append(x)
    return hex_list


def bytes_to_int(data):
    return int.from_bytes(data, 'big')


def int_to_bytes(x, size):
    return x.to_bytes(size, 'big')


def int_to_hex(x, size):
    b = int_to_bytes(x, size)
    return bytes_to_hex(b)
