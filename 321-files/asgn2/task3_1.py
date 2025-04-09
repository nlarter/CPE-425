from Crypto.Util.number import getPrime
from math import ceil

def modular_multiplicative_inverse(e, n):
    t = 0
    next_t = 1
    r = n
    next_r = e

    while next_r:
        quotient = r // next_r
        t, next_t = next_t, t - (quotient * next_t)
        r, next_r = next_r, r - (quotient * next_r)

    if r > 1:
        raise SystemExit(
            f"{e} is not invertible mod {n}"
        )

    if t < 0:
        t += n

    return t


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


def generate_keypair(prime_len):
    if prime_len <= 8:
        raise SystemExit(
            f"primes of length {prime_len} too small for e = 65537"
        )

    p = getPrime(prime_len)
    q = getPrime(prime_len)
    e = 65537

    phi_n = (p - 1) * (q - 1)

    # ensure that e < phi(n) and gcd(e, phi(n)) = 1
    while phi_n <= e or phi_n % e == 0:
        q = getPrime(prime_len)
        phi_n = (p - 1) * (q - 1)

    n = p * q

    # find multiplicative inverse of e w.r.t phi(n)
    d = modular_multiplicative_inverse(e, phi_n)
    
    pubkey = (e, n)
    privkey = (d, n)

    return pubkey, privkey


def encrypt(pubkey, message):
    e, n = pubkey

    m_encoded = message.encode("ascii").hex()
    m_int = int(m_encoded, 16)

    if m_int > n:
        raise SystemExit(
            "Message too long\n"
        )

    m_encrypted = binary_exp(m_int, e, n)
    
    return m_encrypted


def decrypt(privkey, m_encrypted):
    d, n = privkey

    m_int = binary_exp(m_encrypted, d, n)

    message = m_int.to_bytes(ceil(n.bit_length() / 8))\
                   .decode("ascii")\
                   .strip("\x00")

    return message


keysize = 32

print(f"Generating keypair with {keysize}-bit primes")
pubkey, privkey = generate_keypair(keysize)

print(f"Public key (e, n): {pubkey}")
print(f"Private key (d, n): {privkey}")

plaintext = "test567"
print(f"Plaintext: {plaintext}")

ciphertext = encrypt(pubkey, plaintext)
print(f"Ciphertext: {ciphertext}")

output = decrypt(privkey, ciphertext)
print(f"Decrypted plaintext: {output}")

if plaintext == output:
    print("Decrypted plaintext matches original!")
else:
    print("Decrypted plaintext differs from the original")
