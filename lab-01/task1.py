from Crypto.Cipher import AES
from Crypto.Cipher import ARC4 as RC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import binascii
import time

# using modified ecb encrypt function from csc 321
def aes_encrypt(fileText, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(fileText, AES.block_size)

    encrText = cipher.encrypt(padded)
    return encrText

# too slow 2^128 loops due to key size - do not run wont finish
def crack_ecb(ciphertext, key_size=128):
    num_keys = 2 ** key_size

    for i in range(num_keys):
        key = i.to_bytes(key_size // 8, byteorder='big')
        cipher = AES.new(key, AES.MODE_ECB)
        decr = cipher.decrypt(ciphertext)

        if b"this is the wireless security lab" in decr:
            print(f"Key: {key}")
            break
    return

# much faster than ecb 2^40 butt still takes a long time
def crack_rc4(ciphertext, key_size=40):
    num_keys = 2 ** key_size

    for i in range(num_keys):
        key = i.to_bytes(key_size // 8, byteorder='big')
        cipher = RC4.new(key)
        decr = cipher.decrypt(ciphertext)

        if b"this is the wireless security lab" in decr:
            print(f"Key: {key}")
            break
        if i > 1000000:
            break
    return

def rc4_encryption(fileText, key):
    cipher = RC4.new(key)

    encrText = cipher.encrypt(fileText)
    return encrText


if __name__ == "__main__":
    init_ptext = b"this is the wireless security lab"

    aes_key = bytes([0xFF] * 16)
    print("AES MODE\n")
    print(init_ptext)
    aes_encr = aes_encrypt(init_ptext, aes_key)
    print(aes_encr)

    rc4_key = bytes([0xFF] * 5)
    print("\nRC4 Mode\n")
    print(init_ptext)
    rc4_encr = rc4_encryption(init_ptext, rc4_key)
    print(rc4_encr)

    start = time.time()
    crack_rc4(rc4_encr, 40)
    end = time.time()

    print(end - start)
