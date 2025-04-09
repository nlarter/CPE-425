# task 1a, 1b
from hashlib import sha256

def check_hamming_distance(str1: str, str2: str):
    """Checks if the provided strings have a hamming distance of 1 bit."""

    if sum(c1 != c2 for c1, c2 in zip(str1, str2)) != 1:
        raise SystemExit(
            f"Invalid inputs. Not a hamming distance of 1 bit: {str1}, {str2}"
        )

def provide_hashed_digests(m1: str, m2: str):    
    d1 = sha256(m1.encode()).digest()
    d2 = sha256(m2.encode()).digest()
    
    print(f"Digest for message 1: {d1}")
    print(f"Digest for message 2: {d2}")

if __name__ == "__main__":
    # test 1
    print("TEST 1 --")
    
    s1 = "hello"
    s2 = "jello"
    
    print(f"Message 1: {s1}")
    print(f"Message 2: {s2}")
    
    check_hamming_distance(s1, s2)
    provide_hashed_digests(s1, s2)
    
    # test 2
    print("TEST 2 --")

    s1 = "yikes"
    s2 = "bikes"
    
    print(f"Message 1: {s1}")
    print(f"Message 2: {s2}")
    
    check_hamming_distance(s1, s2)
    provide_hashed_digests(s1, s2)
    
    # test 3
    print("TEST 3 --")
    
    s1 = "ee"
    s2 = "ew"
    
    print(f"Message 1: {s1}")
    print(f"Message 2: {s2}")
    
    check_hamming_distance(s1, s2)
    provide_hashed_digests(s1, s2)
    
    # test 4
    print("TEST 4 --")
    
    s1 = "aaa"
    s2 = "aah"
    
    print(f"Message 1: {s1}")
    print(f"Message 2: {s2}")
    
    check_hamming_distance(s1, s2)
    provide_hashed_digests(s1, s2)
    