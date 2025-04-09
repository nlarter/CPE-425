from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import random

def select_private_key(max):
    return random.randint(1, max-1)
    
def calculate_public_key(X, a, q):
    return (a ** X) % q

def generate_secret(Y, X, q):
    return (Y ** X) % q
    
def binary_exp(base, exponent, modulus):
    if modulus == 1:
        return 0
    
    result = 1
    base %= modulus

    while exponent > 0:
        if exponent % 2:
            result = (result * base) % modulus

        base = (base ** 2) % modulus
        exponent = exponent >> 1

    return result

def simulate_diffie_hellman_mitm(q, a, m0, m1):
    # alice sends q, a to bob
    attack = False
    #task 2 part 2 - change a to 1, q - 1, or q
    #a = 1
    #a = q - 1
    a = q
    attack = True

    # alice and bob privately compute their private and public keys
    Xa = select_private_key(max=q)
    Ya = binary_exp(a, Xa, q)
    
    Xb = select_private_key(max=q)
    Yb = binary_exp(a, Xb, q)
    # alice and bob send eachother their public keys

    #mallory modifies Ya, Yb -> q
    #commented out for task 2 part 2
    #Ya = q
    #Yb = q
    #attack = True

    # alice and bob calculate their secrets
    sa = generate_secret(Yb, Xa, q)
    sb = generate_secret(Ya, Xb, q)

    #sa and sb are the same (0) and mallory knows this, because Ya and Yb are both equal to q
    
    if sa != sb:
        raise SystemExit(
            f"Calulated different symmetric keys. sa: {sa}, sb: {sb}"
        )
        
    # alice and bob calculate their symmetric key
    Ka = sha256(str(sa).encode()).digest()[:16]
    Kb = sha256(str(sb).encode()).digest()[:16]

    #mallory can also compute the encryptionn key through knowing sa and sb = 0
    if attack is True:
        Km = sha256(str(sb).encode()).digest()[:16]
    else:
        print("No attack or unsuccessful attack")
        exit()
    
    # AES-CBC encrypt alice and bob's messages
    iv = b'\x00' * 16
    
    cipher_a = AES.new(Ka, AES.MODE_CBC, iv)
    cipher_b = AES.new(Kb, AES.MODE_CBC, iv)
    cipher_m = AES.new(Km, AES.MODE_CBC, iv)
    
    #alice encrypts and sends message to bob
    print(f"\nWhat Alice sent: {m0}")
    c0 = cipher_a.encrypt(pad(m0, AES.block_size))

    #mallory intercepts and decrypts alice's message

    decipher_m = AES.new(Km, AES.MODE_CBC, iv)
    cm0 = unpad(decipher_m.decrypt(c0), AES.block_size)

    # mallory now has access to alice's plaintext message
    print(f"\nmallory now has from alice: {cm0}")

    #if mallory wants to change the message and send the wrong thing to bob
    # mallory doesn't need to change it, it can also just be read
    cm0 = b"i hate bob"
    print(f"\nWhat mallory changed Alice's message to: {cm0}")
    mal_message = cipher_m.encrypt(pad(cm0, AES.block_size))

    c0 = mal_message

    # bob deciphers what he thinks is alice's message
    decipher_b = AES.new(Kb, AES.MODE_CBC, iv)

    m0_descrypted = unpad(decipher_b.decrypt(c0), AES.block_size)

    print(f"what bob recieved: {m0_descrypted}")

    # bob encrypts and sends back his message to who he thinks is alice
    c1 = cipher_b.encrypt(pad(m1, AES.block_size))
    print(f"\nWhat bob sent: {m1}")

    #mallory gets bob's encrypted message
    decipher_m = AES.new(Km, AES.MODE_CBC, iv)
    cm1 = unpad(decipher_m.decrypt(c1), AES.block_size)

    print(f"\nmallory now has from bob: {cm1}")

    #mallory can change the message, or just re encrypt it and send it to alice
    #here mallory doesn't change it
    cipher_m = AES.new(Km, AES.MODE_CBC, iv)
    mal_message_b = cipher_m.encrypt(pad(cm1, AES.block_size))

    #mallory sends the unchanged message to alice after reading it

    c1 = mal_message_b

    # AES-CBC decrypt bob and alice's messages
    decipher_a = AES.new(Ka, AES.MODE_CBC, iv)
    decipher_b = AES.new(Kb, AES.MODE_CBC, iv)
    
    m1_descrypted = unpad(decipher_a.decrypt(c1), AES.block_size)
    m0_descrypted = unpad(decipher_b.decrypt(c0), AES.block_size)
    
    print(f"\nWhat Alice thinks Bob sent: {m1_descrypted}")
    print(f"what Bob thinks Alice sent: {m0_descrypted}")
    

if __name__ == "__main__":
    # small group test
    q = 37
    a = 5
    
    alice_message = b"Hi Bob!"
    bob_message = b"Hi Alice!"
    
    print("Small numbers :)")
    simulate_diffie_hellman_mitm(q, a, alice_message, bob_message)
    
    # "real life" numbers
    q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371" , 16)
    a = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

    print("\nReal life numbers")
    simulate_diffie_hellman_mitm(q, a, alice_message, bob_message)
