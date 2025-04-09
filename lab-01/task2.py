from Crypto.Cipher import AES
from Crypto.Cipher import ARC4 as RC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util import Counter

# using modified ecb encrypt function from csc 321
def ecb_encrypt(fileText, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(fileText, AES.block_size)

    encrText = cipher.encrypt(padded)
    print(f"Encrypted: {encrText}")
    index = len(encrText) // 2
    encrText = encrText[:index] + b'0' + encrText[index+1:]
    decr = cipher.decrypt(encrText)
    print(f"Decrypted: {decr}")
    print(f"Plaintext: {fileText}")
    return encrText

def cbc_encrypt(fileText, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(fileText, AES.block_size)

    encrText = cipher.encrypt(padded)
    print(f"Encrypted: {encrText}")
    index = len(encrText) // 2
    encrText = encrText[:index] + b'0' + encrText[index+1:]

    dec_cipher = AES.new(key, AES.MODE_CBC, iv)
    decr = dec_cipher.decrypt(encrText)
    print(f"Decrypted: {decr}")
    print(f"Plaintext: {fileText}")
    return encrText, iv

def cfb_encrypt(fileText, key, iv):
    cipher = AES.new(key, AES.MODE_CFB, iv)

    encrText = cipher.encrypt(fileText)
    print(f"Encrypted: {encrText}")
    index = len(encrText) // 2
    encrText = encrText[:index] + b'0' + encrText[index+1:]

    dec_cipher = AES.new(key, AES.MODE_CFB, iv)
    decr = dec_cipher.decrypt(encrText)
    print(f"Decrypted: {decr}")
    print(f"Plaintext: {fileText}")
    return encrText, iv

def ofb_encrypt(fileText, key, iv):
    cipher = AES.new(key, AES.MODE_OFB, iv)

    encrText = cipher.encrypt(fileText)
    print(f"Encrypted: {encrText}")
    index = len(encrText) // 2
    encrText = encrText[:index] + b'0' + encrText[index+1:]

    dec_cipher = AES.new(key, AES.MODE_OFB, iv)
    decr = dec_cipher.decrypt(encrText)
    print(f"Decrypted: {decr}")
    print(f"Plaintext: {fileText}")
    return encrText, iv

def ctr_encrypt(fileText, key, iv):
    iv = int.from_bytes(iv, byteorder='big')
    ctr = Counter.new(128, initial_value=iv)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    encrText = cipher.encrypt(fileText)
    print(f"Encrypted: {encrText}")
    index = len(encrText) // 2
    encrText = encrText[:index] + b'0' + encrText[index+1:]

    dec_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    decr = dec_cipher.decrypt(encrText)
    print(f"Decrypted: {decr}")
    print(f"Plaintext: {fileText}")
    return encrText


def rc4_encryption(fileText, key):
    cipher = RC4.new(key)

    encrText = cipher.encrypt(fileText)
    return encrText


if __name__ == "__main__":
    init_ptext = b"testwordtestword" * 4
    iv = get_random_bytes(16)

    aes_key = bytes([0xFF] * 16)
    print("-------ECB-------\n")
    ecb_encrypt(init_ptext, aes_key)

    print("\n-------CBC-------\n")
    cbc_encrypt(init_ptext, aes_key, iv)

    print("\n-------CFB-------\n")
    cfb_encrypt(init_ptext, aes_key, iv)

    print("\n-------OPB-------\n")
    ofb_encrypt(init_ptext, aes_key, iv)

    print("\n-------CTR-------\n")
    ctr_encrypt(init_ptext, aes_key, iv)
