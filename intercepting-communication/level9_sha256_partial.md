# Problem Statement
As you saw, raw RSA signatures are a bad idea, as they can be forged. In practice, what people sign are cryptographic hashes of things. A hash is a one-way function that takes an arbitrary amount of input (e.g., bytes or gigabytes or more) and outputs a short (e.g., 32 bytes) of output hash. Any changes in the input to the hash will diffuse all over the resulting cryptographic hash in a way that is not reversible.

Thus, secure hashes are a good representation for the original data: if Alice signs a hash of a message, that message can be seen as being signed as well. Better yet, since hashes are not controllably reversible or modifiable, an attacker being able to modify a hash does not allow them to forge a signature on a new message.

The bane of cryptographic hashing algorithms is collision. If an attacker can craft two messages that hash to the same thing, the security of any system that depends on the hash (such as the RSA signature scheme described above) might be compromised. For example, consider that the security of bitcoin depends fully on the collision resistance of SHA256...

While full collisions of SHA256 don't exist, some applications use partial hash verification. This is not a great practice, as it makes it easier to brute-force a collision.

In this challenge you will do just that, hashing data with a Secure Hash Algorithm (SHA256). You will find a small hash collision. Your goal is to find data, which when hashed, has the same hash as the secret. Only the first 3 bytes of the SHA256 hash will be checked.


## Observations 
- This one is pretty straight forward, but if you don't find solutions right away I'd check how the data is being converted from hex to bytes and viceversa first, before trying to add input bytes.
  

# Solution
```
#!/usr/bin/exec-suid -- /usr/bin/python3 -I

import hashlib
from pwn import *

prefix_len = 6

p = process("/challenge/run")

#flag_hash[:prefix_length]='b373ea'

line = p.recvuntil(b"input? ")
print(f"Received: {line}")
target = bytes.fromhex(line.split(b"='")[1].split(b"'")[0].decode()) # take the first 3 bytes

colliding_input = 0
search_space = 2**24 # minimum search space is (2**8)**3. If no results, expanding 2**32 should be enough
collision_found = False

print(f"Target prefix: {target}")
for i in range(1, search_space):
    digest_prefix = hashlib.sha256(i.to_bytes(3, "big")).digest()
    if i & (i-1) == 0: # check i for powers of two
        print(f"Reached i = {i}: prefix = {digest_prefix[:3]}") # exponential verification 
    if target == digest_prefix[:3]:
        print(f"\n*******************\nCollision Found!\n*****************\n{digest_prefix[:3]} == {target}\ni = {i}")
        colliding_input = i
        collision_found = True        
        break

if not collision_found:
    print("Search space exhausted, try an extra input byte")
    exit()

print(f"colliding string: {colliding_input:x}")
p.sendline(f"{colliding_input:x}".encode("latin"))
for i in range(4):
    print(p.recvline())


```
