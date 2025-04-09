from Crypto.Util.number import getPrime, inverse
from Crypto.Cipher import AES
from hashlib import sha256
import os

# Step 1: RSA Key Generation (Alice)
def generate_rsa_keypair(bits=512):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi_n) 

    return (e, n), (d, n)  # (Public Key, Private Key)

# Step 2: Bob Encrypts Symmetric Key with RSA
def rsa_encrypt(pubkey, message_int):
    e, n = pubkey
    return pow(message_int, e, n) 

# Step 3: Mallory Modifies Ciphertext (Attack)
def mallory_attack(ciphertext, e, n):
    r = 3  # Mallory picks arbitrary value r
    modified_ciphertext = (ciphertext * pow(r, e, n)) % n 
    return modified_ciphertext, r  # Returns modified c' and r for validation

# Step 4: Alice Decrypts the Modified Ciphertext
def rsa_decrypt(privkey, ciphertext):
    d, n = privkey
    return pow(ciphertext, d, n) 

# Step 5: AES Encryption (Alice)
def aes_encrypt(key, plaintext):
    key_hash = sha256(key.to_bytes((key.bit_length() + 7) // 8, "big")).digest()
    iv = os.urandom(16)  # Random IV
    cipher = AES.new(key_hash, AES.MODE_CBC, iv)
    
    pad_len = 16 - len(plaintext) % 16
    padded_plaintext = plaintext + (chr(pad_len) * pad_len).encode()

    ciphertext = iv + cipher.encrypt(padded_plaintext)
    return ciphertext

# Step 6: AES Decryption (Bob)
def aes_decrypt(key, ciphertext):
    key_hash = sha256(key.to_bytes((key.bit_length() + 7) // 8, "big")).digest()
    iv, encrypted_message = ciphertext[:16], ciphertext[16:]
    
    cipher = AES.new(key_hash, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_message)
    
    pad_len = decrypted_padded[-1]
    return decrypted_padded[:-pad_len]

# ------------------------------
# Simulating the Attack
# ------------------------------

# Generate RSA keypair
pubkey, privkey = generate_rsa_keypair()
print(f"Public Key (e, n): {pubkey}")
print(f"Private Key (d, n): {privkey}")

# Bob selects symmetric key s
s = 123456  # Example symmetric key
print(f"\nBob's original symmetric key: {s}")

# Bob encrypts s
ciphertext = rsa_encrypt(pubkey, s)
print(f"Bob sends ciphertext: {ciphertext}")

# Mallory modifies ciphertext
modified_ciphertext, r = mallory_attack(ciphertext, pubkey[0], pubkey[1])
print(f"\nMallory modifies ciphertext to: {modified_ciphertext} (using r = {r})")

# Alice decrypts modified ciphertext
s_prime = rsa_decrypt(privkey, modified_ciphertext)
print(f"\nAlice receives and decrypts s': {s_prime}")

# Alice computes AES key
k_prime = sha256(s_prime.to_bytes((s_prime.bit_length() + 7) // 8, "big")).digest()

# Alice encrypts message using AES
plaintext = "Hi Bob!".encode()
encrypted_message = aes_encrypt(s_prime, plaintext)
print(f"\nAlice sends AES-encrypted message: {encrypted_message.hex()}")

# Bob attempts to decrypt (but he has the original s, not s')
try:
    decrypted_message = aes_decrypt(s, encrypted_message)  # Bob uses original s
    decrypted_text = decrypted_message.decode()
    
    if decrypted_text != "Hi Bob!":
        raise ValueError("Decryption succeeded, but message is incorrect.")

    print(f"\nBob decrypts: {decrypted_text}")

except Exception as e:
    print(f"\nBob's decryption failed due to incorrect key: {e}")
