from lib import *

def join_64bits(text):
    crypted_text = 0
    for i in reversed(range(len(text))):
        crypted_text |= text[i]
        if i != 0:
            crypted_text = crypted_text << 64
    return crypted_text



def GOST_28147_89_ECB(text, keys, mode):
    text = [feistel_cipher(i, keys, mode) for i in text]
    crypted_text = join_64bits(text)
    return crypted_text


def GOST_28147_89_CBC(text, keys, mode):
    vec_init = 0x1234567891234567
    if mode == "e":
        text[0] = text[0] ^ vec_init
        text[0] = feistel_cipher(text[0], keys, mode)
        for i in range(1, len(text)):
            text[i] = text[i] ^ text[i - 1]
            text[i] = feistel_cipher(text[i], keys, mode)
    elif mode == "d":
        temp_one = text[0]
        text[0] = feistel_cipher(text[0], keys, mode)
        text[0] = text[0] ^ vec_init
        for i in range(1, len(text)):
            temp_two = text[i]
            text[i] = feistel_cipher(text[i], keys, mode)
            text[i] = text[i] ^ temp_one
            temp_one = temp_two
    crypted_text = join_64bits(text)
    return crypted_text

def GOST_28147_89_CFB(text, keys, mode):
    vec_init = 0x1234567891234567
    if mode == "e":
        vec_init = feistel_cipher(vec_init, keys, mode)
        text[0] = vec_init ^ text[0]
        for i in range(1, len(text)):
            vec_init = feistel_cipher(text[i - 1], keys, mode)
            text[i] = vec_init ^ text[i]
    if mode == "d":
        vec_init = feistel_cipher(vec_init, keys, "e")
        temp = text[0]
        text[0] = vec_init ^ text[0]
        for i in range(1, len(text)):
            vec_init = feistel_cipher(temp, keys, "e")
            temp = text[i]
            text[i] = vec_init ^ text[i]
    crypted_text = join_64bits(text)
    return crypted_text

def GOST_28147_89_OFB(text, keys, mode):
    vec_init = 0x1234567891234567
    if mode == "e":
        vec_init = feistel_cipher(vec_init, keys, mode)
        text[0] = vec_init ^ text[0]
        for i in range(1, len(text)):
            vec_init = feistel_cipher(vec_init, keys, mode)
            text[i] = vec_init ^ text[i]
    if mode == "d":
        vec_init = feistel_cipher(vec_init, keys, "e")
        text[0] = vec_init ^ text[0]
        for i in range(1, len(text)):
            vec_init = feistel_cipher(vec_init, keys, "e")
            text[i] = vec_init ^ text[i]
    crypted_text = join_64bits(text)
    return crypted_text



def GOST_28147_89(text, key, mode="e", op_mode="ECB",):
    temp = 0
    if len(hex(text)[2:]) % 16 > 0:
        temp = 1
    text = [(text >> (64 * i)) & 0xFFFFFFFFFFFFFFFF for i in range(len(hex(text)) // 16 + temp)]
    if temp == 1:
        text[len(text) - 1] = text[len(text) - 1] << (64 - len(hex(text[len(text) - 1]) * 4))
    keys = gen_key(key)

    if op_mode == "ECB":
        crypted_text = GOST_28147_89_ECB(text, keys, mode)
        return crypted_text
    elif op_mode == "CBC":
        crypted_text = GOST_28147_89_CBC(text, keys, mode)
        return crypted_text
    elif op_mode == "CFB":
        crypted_text = GOST_28147_89_CFB(text, keys, mode)
        return crypted_text
    elif op_mode == "OFB":
        crypted_text = GOST_28147_89_OFB(text, keys, mode)
        return crypted_text



def main():
    text = askii_to_bin(file_read('EnText.txt'))
    text = int(text, 2)
    key = 0x287fc759c1ad6b59ac8597159602217e9a03381dcd943c4719dcca000fb2b577

    mode = input("Введите режим работы {ECB, CBC, CFB, OFB}: ")
    print(f"Режим работы {mode}")

    crypted_text = GOST_28147_89(text, key, "e", mode)
    encrypted_text = GOST_28147_89(crypted_text, key, "d", mode)

    print(f"Исходный текст {file_read('EnText.txt')}")
    print(f"Исходный текст в числовом обозначении {text}")

    print(f"\nКлюч {key}")

    print(f"\nЗашифрованный текст {int_to_askii(crypted_text)}")
    print(f"Зашифрованный текст в числовом обозначении {crypted_text}")

    print(f"\nДешифрованный текст {int_to_askii(encrypted_text)}")
    print(f"Дешифрованный текст в числовом обозначении {encrypted_text}")

    file_write('DecText.txt', int_to_askii(crypted_text))


if __name__ == '__main__':
    main()
