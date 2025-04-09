from bcrypt import *
from nltk.corpus import words
import sys

if len(sys.argv) != 2:
    raise SystemExit(
        "Invalid arguments"
    )

shadow = open(sys.argv[1], "r")

def filter_len(word):
    return 6 <= len(word) <= 10

wordlist = list(filter(filter_len, words.words()))

names = {}
salts = {}
hashes = {}

for line in shadow:
    offset = line.find(":")

    name = line[:offset]
    salt = line[offset+1:offset+31].encode()
    hash = line[offset+1:].strip().encode()
    workfactor = salt[4:6]

    if workfactor in names.keys():
        names[workfactor].append(name)
    else:
        names[workfactor] = [name]

    if not workfactor in salts.keys():
        salts[workfactor] = salt

    if workfactor in hashes.keys():
        hashes[workfactor].append(hash)
    else:
        hashes[workfactor] = [hash]

shadow.close()


for wf in names.keys():
    namelst = names[wf]
    salt = salts[wf]
    hashlst = hashes[wf]
    
    for word in wordlist:
        if len(hashlst) == 0:
            break
        
        currhash = hashpw(word.encode(), salt)
        if currhash in hashlst:
            index = hashlst.index(currhash)
            print(f"{namelst.pop(index)}: {word}")
            hashlst.pop(index)
