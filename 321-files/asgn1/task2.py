from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from task1 import *

def submit(inputString, key, vector):
    encodedString = inputString.replace("=", "%3D").replace(";", "%3B")
    plainText = pad(bytes("userid=456;userdata=" +
                          encodedString + 
                          ";session-id=31337", "utf-8"))
    return cbc_encrypt(plainText, key, vector)

def verify(cipherText, key, vector):
    plainText = cbc_decrypt(cipherText, key, vector)
    return plainText.find(b";admin=true;") >= 0


key = get_random_bytes(16)

vector = get_random_bytes(16)

cipherText = submit("hello!", key, vector)
print(f"unmodified cipher text: {cipherText}")

print("Testing unmodified ciphertext:")
print("Admin: {}".format(verify(cipherText, key, vector)))

knownPlaintext = "a" * 48
xorTemplate = bytes(a ^ b for a, b in zip(b"a" * 12, b";admin=true;"))

cipherText = submit(knownPlaintext, key, vector)

xorTemplate = bytes(32) + xorTemplate + bytes(len(cipherText) - 44)

modifiedCipherText = bytes(a ^ b for a, b in zip(cipherText, xorTemplate))
print(f"modified cipher text: {modifiedCipherText}")

print("Testing modified ciphertext:")
print("Admin: {}".format(verify(modifiedCipherText, key, vector)))
