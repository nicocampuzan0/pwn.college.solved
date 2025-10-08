# Problem Statement
In this challenge you will hash data with a Secure Hash Algorithm (SHA256). You will compute a small proof-of-work. Your goal is to find response data, which when appended to the challenge data and hashed, begins with 2 null-bytes.

## Observations
- This is one of the easiest in the whole module, but it did take me 2 tries to figure out that I was prepending the data instead of appending it
# Solution

```
import hashlib
from base64 import b64decode, b64encode

challenge = b64decode("sJtvTMBaD5yM5NsZ6tLJ2g2uDVMfyckpIkovYTtMYiM=")
search_space = 2**24 # minimum search space is (2**8)**3, but I can't find it, so we'll add an extra byte to make it (2**8)**4
collision_found = False

for i in range(1, search_space):
    digest_prefix = hashlib.sha256(challenge + i.to_bytes(3, "big")).digest()
    if i & (i-1) == 0: # check i for powers of two
        print(f"Reached i = {i}: prefix = {digest_prefix[:3]}") # exponential verification 
    if digest_prefix[:2] == b'\x00\x00':
        print(f"\n*******************\nWork Completed!\n*****************\n{digest_prefix}\ni = {i}")
        colliding_input = i
        collision_found = True        
        break

if not collision_found:
    print("Search space exhausted, try an extra input byte")
    exit()

print(f"target prefix: {b64encode(colliding_input.to_bytes(3, 'big'))}")

```
