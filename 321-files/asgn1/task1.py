from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys


def cbc_decrypt(fileText, key, vector):
    cipher = AES.new(key, AES.MODE_ECB)
    decrText = b""
    prev_block = vector
    for i in range(0, len(fileText), 16):
        currBlock = fileText[i : i + 16]
        decrBlock = cipher.decrypt(currBlock)
        decrBlock = bytes(a ^ b for a, b in zip(decrBlock, prev_block))
        decrText += decrBlock
        prev_block = currBlock
    return unpad(decrText)


def cbc_encrypt(fileText, key, vector):
    cipher = AES.new(key, AES.MODE_ECB)
    if len(fileText) % 16 != 0:
        fileText = pad(fileText)
    encrText = b""
    prev_block = vector
    for i in range(0, len(fileText), 16):
        currBlock = fileText[i : i + 16]
        currBlock = bytes(a ^ b for a, b in zip(currBlock, prev_block))
        encrBlock = cipher.encrypt(currBlock)
        encrText += encrBlock
        prev_block = encrBlock
    return encrText


def ecb_decrypt(fileText, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decr_text = b""
    for i in range(0, len(fileText), 16):
        currBlock = fileText[i : i + 16]
        decr_text += cipher.decrypt(currBlock)
    return decr_text


def ecb_encrypt(fileText, key):
    cipher = AES.new(key, AES.MODE_ECB)
    if len(fileText) % 16 != 0:
        fileText = pad(fileText)

    encrText = b""
    for i in range(0, len(fileText), 16):
        currBlock = fileText[i : i + 16]
        encrText += cipher.encrypt(currBlock)
    return encrText


def read_bmp(filename):
    with open(filename, "rb") as f:
        header = f.read(54)
        body = f.read()
    return header, body


def write_bmp(filename, header, enc_body):
    with open(filename, "wb") as f:
        f.write(header)
        f.write(enc_body)
    return


def pad(fileText):
    block = 16
    padding = block - (len(fileText) % block)
    return fileText + bytes([padding] * padding)


def unpad(fileText):
    padding_len = fileText[-1]
    
    if padding_len > len(fileText):
        raise ValueError("Invalid padding :(")
    
    return fileText[:-1]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "Invalid number of arguments. Run as: python task1.py '[filename]'"
        )

    header, body = read_bmp(sys.argv[1])

    key = get_random_bytes(16)

    enc_body = ecb_encrypt(body, key)

    write_bmp("./files/out-test-txt.txt", header, enc_body)

    ## BMP File encryption

    # ecb encryption
    header, body = read_bmp("./files/cp-logo.bmp")

    key = get_random_bytes(16)

    enc_body = ecb_encrypt(body, key)

    write_bmp("./files/out-test-ecb.bmp", header, enc_body)

    # ecb decryption
    header, body = read_bmp("./files/out-test-ecb.bmp")

    dec_body = ecb_decrypt(body, key)

    write_bmp("./files/out-dec-ecb-test.bmp", header, dec_body)

    # cbc encryption
    header, body = read_bmp("./files/cp-logo.bmp")

    key = get_random_bytes(16)

    vector = get_random_bytes(16)

    enc_body = cbc_encrypt(body, key, vector)

    write_bmp("./files/out-test-cbc.bmp", header, enc_body)

    # ecb decryption
    header, body = read_bmp("./files/out-test-cbc.bmp")

    dec_body = cbc_decrypt(body, key, vector)

    write_bmp("./files/out-dec-cbc-test.bmp", header, dec_body)
