# task 1a, 1b
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
import random
import string
import time

def check_hamming_distance(str1: str, str2: str) -> bool:
    """Checks if the provided strings have a hamming distance of 1 bit

    Returns:
        bool: True if the hamming distance is 1, False otherwise.
    """
    return sum(c1 != c2 for c1, c2 in zip(str1, str2)) == 1
    

def provide_hashed_digests(m1: str, m2: str):
    if not check_hamming_distance(m1, m2):
        raise SystemExit(
            f"Invalid inputs. Not a hamming distance of 1 bit: {m1}, {m2}"
        )
        
    d1 = sha256(m1).hexdigest()
    d2 = sha256(m2).hexdigest()
    
    print(f"Digest for message 1: {d1}")
    print(f"Digest for message 2: {d2}")

def trunc_hashed(m1: str, m2: str, bits: int):
    """
        takes the first <bits> bits from the input strings
    """
    if not bits >= 8 and not bits <= 50 and not bits % 2 == 0:
        raise SystemExit(
            f"Invalid bit amount: even number between 8 and 50"
        )
    chars_to_trunc = int(bits / 4)
    
    d1 = sha256(m1).hexdigest()
    d2 = sha256(m2).hexdigest()

    tm1 = d1[:chars_to_trunc]
    tm2 = d2[:chars_to_trunc]

    print(f"Digest for message 1: {d1}")
    print(f"Digest for message 2: {d2}")

    print(f"Truncated m1: {tm1}")
    print(f"Truncated m2: {tm2}")

    return tm1, tm2

def find_collision(bits: int):
    """
        dict[val] -> val gets hashed -> what is returned from that query is the value
    """
    hashtable = {}
    equal = False
    chars_to_trunc = int(bits / 4)
    num_tries = 0

    start = time.time()

    """
        loops until it finds a string with a hash value already in the table, saving time,
        number of inputs, and bits taken. will end when collision is found unless the 
        two input strings are the same - if that happens keep going

        takes about 10 mins to run the loop in main for all 21 loop iterations
    """

    while not equal:
        m1 = generate_message(length=10)
        hash = sha256(m1.encode()).hexdigest()
        tm1 = hash[:chars_to_trunc]

        if tm1 in hashtable and not m1 == hashtable[tm1]:
            m2 = hashtable[tm1]
            print(f"Collision found, message 1: {m1}, message 2: {m2}")
            print(f"Hashed: {tm1}")
            equal = True
        else:
            hashtable[tm1] = m1
        num_tries += 1
    end = time.time()

    print(f"Time taken for {bits} bits: {end - start}")
    print(f"Amount of inputs for {bits} bits: {num_tries}\n")

    return end - start, num_tries, bits

"""
    randomly generates a string of length length for hashing
    i set length to 10 when i called it, not for any reason, can be changed
"""
def generate_message(length):
    letters = string.ascii_letters
    message = ''.join(random.choice(letters) for _ in range(length))
    return message

if __name__ == "__main__":
    # test 1
    print("TEST 1 --")
    
    s1: str = b"hello"
    s2: str = b"jello"
    
    print(f"Message 1: {s1}")
    print(f"Message 2: {s2}")
    
    provide_hashed_digests(s1, s2)

    print("TASK 2 --")

    s1: str = b"hello"
    s2: str = b"jello"

    trunc_bits = 8

    trunc_hashed(s1, s2, trunc_bits)


    start = time.time()

    with open(f"task-1c-results/time-inputs-vs-bits.txt", "w") as outfile:
        """
            writes the time, # inputs, and # bits to a file in the form 
            <time>, <num collisions>, <num bits>
            the filename will be 
            time-inputs-vs-bits.txt in the task-1c-results directory
            where <num bits> is the amount of bits taken from the hexdigest (8-50 evens)
        """
        for bits in range(8, 51, 2):
            print(f"Bits hashed: {bits}")
            runtime, cols, nbiits = find_collision(bits)
            outfile.write(f"{runtime}, {cols}, {bits}\n")

    end = time.time()

    print(f"Total time to find collisions for 8, 10, 12, ..., 50 bits: {end - start}")

    """
        commented out tests 2+ to limit output to test 1 from task 1 and task2 output
    
        # test 2
        print("TEST 2 --")

        s1: str = b"hello"
        s2: str = b"jello"
        
        print(f"Message 1: {s1}")
        print(f"Message 2: {s2}")
        
        provide_hashed_digests(s1, s2)
        
        # test 3
        print("TEST 3 --")
        
        s1: str = b"ee"
        s2: str = b"ew"
        
        print(f"Message 1: {s1}")
        print(f"Message 2: {s2}")
        
        provide_hashed_digests(s1, s2)
        
        # test 4
        print("TEST 4 --")
        
        s1: str = b"aaa"
        s2: str = b"aah"
        
        print(f"Message 1: {s1}")
        print(f"Message 2: {s2}")
        
        provide_hashed_digests(s1, s2)

    """
    