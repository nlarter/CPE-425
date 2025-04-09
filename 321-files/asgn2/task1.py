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

def simulate_diffie_hellman(q, a, m0, m1):
    # alice sends q, a to bob
    
    # alice and bob privately compute their private and public keys
    Xa = select_private_key(max=q)
    Ya = calculate_public_key(Xa, a, q)
    
    Xb = select_private_key(max=q)
    Yb = calculate_public_key(Xb, a, q)
    
    # alice and bob send eachother their public keys
     
    # alice and bob calculate their secrets
    sa = generate_secret(Yb, Xa, q)
    sb = generate_secret(Ya, Xb, q)
    
    if sa != sb:
        raise SystemExit(
            f"Calulated different symmetric keys. sa: {sa}, sb: {sb}"
        )
        
    # alice and bob calculate their symmetric key
    Ka = sha256(str(sa).encode()).digest()[:16]
    Kb = sha256(str(sb).encode()).digest()[:16]
    
    # AES-CBC encrypt alice and bob's messages
    iv = b'\x00' * 16
    
    cipher_a = AES.new(Ka, AES.MODE_CBC, iv)
    cipher_b = AES.new(Kb, AES.MODE_CBC, iv)
    
    c0 = cipher_a.encrypt(pad(m0, AES.block_size))
    c1 = cipher_b.encrypt(pad(m1, AES.block_size))
    
    # alice sends her encryptes message, then bob sends his
    
    # AES-CBC decrypt bob and alice's messages
    decipher_a = AES.new(Ka, AES.MODE_CBC, iv)
    decipher_b = AES.new(Kb, AES.MODE_CBC, iv)
    
    m1_descrypted = unpad(decipher_a.decrypt(c1), AES.block_size)
    m0_descrypted = unpad(decipher_b.decrypt(c0), AES.block_size)
    
    print(f"Alice's message to Bob: {m0_descrypted}")
    print(f"Bob's message to Alice: {m1_descrypted}")
    

if __name__ == "__main__":
    # small group test
    q = 37
    a = 5
    
    alice_message = b"Hi Bob!"
    bob_message = b"Hi Alice!"
    
    print("Small numbers-")
    simulate_diffie_hellman(q, a, alice_message, bob_message)
    
    # "real life" numbers
    q = int("""B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AE
            A906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45B
            F37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371""" , 16)
    a = int("""A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B
            01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779
            D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5""", 16)

    print("\nReal life numbers-")
    simulate_diffie_hellman(q, a, alice_message, bob_message)
