def file_read(path):
    with open(path, "r") as f:
        text = f.read()
    return text


def file_write(path, text):
    with open(path, "w") as f:
        print(text, file=f)


def int_to_bin(int_num, length=8):
    bin_num = bin(int_num)[2:]
    while len(bin_num) < length:
        bin_num = "0" + bin_num
    return bin_num

def split_bits_to_bits(text_bin, lg):
    list_bits = []
    while len(text_bin) > 0:
        list_bits.append(text_bin[:lg])
        text_bin = text_bin[lg:]
    return list_bits


def askii_to_bin(string):
    res = ""
    string = string.encode('cp1251')
    for i in string:
        res += int_to_bin(i)
    return res


def int_to_askii(text):
    symbols = [(text >> (8 * i)) & 0xFF for i in range(len(hex(text)) // 2)]
    str = ""
    for i in symbols:
        str += bytes([i]).decode('cp1251')
    return str[::-1]


def feistel_cipher_round(N, key):
    sbox = (
        (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
        (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
        (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
        (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
        (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
        (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
        (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
        (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12),
    )
    temp = N ^ key  # складываем по модулю
    output = 0
    for i in range(8):
        output |= ((sbox[i][(temp >> (4 * i)) & 0b1111]) << (4 * i))
    return ((output >> 11) | (output << (32 - 11))) & 0xFFFFFFFF


def encrypt_round(left_part, right_part, round_key):
    return right_part, left_part ^ feistel_cipher_round(right_part, round_key)


def decrypt_round(left_part, right_part, round_key):
    return right_part ^ feistel_cipher_round(left_part, round_key), left_part


def feistel_cipher(text64bits, keys, mode="e"):
    if mode == "e":
        left_part = text64bits >> 32
        right_part = text64bits & 0xFFFFFFFF
        for i in range(24):
            left_part, right_part = encrypt_round(left_part, right_part, keys[i % 8])
        for i in range(8):
            left_part, right_part = encrypt_round(left_part, right_part, keys[7 - i])
        return (left_part << 32) | right_part
    elif mode == "d":
        left_part = text64bits >> 32
        right_part = text64bits & 0xFFFFFFFF
        for i in range(8):
            left_part, right_part = decrypt_round(left_part, right_part, keys[i])
        for i in range(24):
            left_part, right_part = decrypt_round(left_part, right_part, keys[(7 - i) % 8])
        return (left_part << 32) | right_part


def gen_key(key):
    keys = list()
    keys = [(key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]
    return keys
