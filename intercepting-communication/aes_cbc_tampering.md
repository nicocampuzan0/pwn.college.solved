# Problem Description
CBC-based cryptosystems XOR the previous block's ciphertext to recover the plaintext of a block after decryption. This done for many reasons, including:

  - This XOR is what separates it from ECB mode, and we've seen how fallible ECB is.
  - If it XORed the plaintext of the previous block instead of the ciphertext, the efficacy would be dependent on the plaintext itself (for example, if the plaintext was all null bytes, the XOR would have no effect). Aside from reducing the chaining effectiveness, this could leak information about the plaintext (big no no in cryptosystems)!
  - If it XORed the plaintext of the previous block instead of the ciphertext, the "random access" property of CBC, where the recipient of a message can decrypt starting from any block, would be lost. The recipient would have to recover the previous plaintext, for which they would have to recover the one before that, and so on all the way to the IV.

Unfortunately, in situations where the message could be modified in transit (think: Intercepting Communications), a crafty attacker could directly influence the resulting decrypted plaintext of block N by XORing carefully-chosen values into the ciphertext of block N-1. This would corrupt block N-1 (because it would decrypt to garbage), but depending on the specific situation, this might be acceptable. Moreover, doing this to the IV allows the attacker to XOR the plaintext of the first block without corrupting any block!

In security terms, CBC preserves (imperfectly, as we'll see in the next few challenges) Confidentiality, but does not preserve Integrity: the messages can be tampered with by an attacker!

We will explore this concept in this level, where a task dispatcher will dispatch encrypted tasks to a task worker. Can you force a flag disclosure?


## Observations
- From https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/ 
  - <img width="896" height="730" alt="image" src="https://github.com/user-attachments/assets/16606c3a-d752-4c66-b505-9a2e5cc1f7f1" />

- The IV is XOR'd with the first block BEFORE encryption
- XOR is a commutative, self-inverting operation
- There's also only one block of input so by design we have to figure something out with the 2 operations that take place with the plaintext: XOR and / or decryption
  - We know the plaintext is `sleep`, and we know the IV.
  - We know the ciphertext is `sleep ^ IV`, but we also know messing with the ciphertext to affect the decryption operation is a blind attack that should be computationally infeasible by definition.
  - We know that XOR is commutative and self-inverse. These two combined properties mean we can XOR inverses of the previous operators in any order and cancel them.
    - Therefore, if we cancel out the known operators, and XOR that with our chosen plaintext, the worker will end up with just our chosen plaintext.


# Solution
```
#!/opt/pwn.college/python

import os
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

# Dispatcher code for reference commented out below
#key = open("/challenge/.key", "rb").read()
#cipher = AES.new(key=key, mode=AES.MODE_CBC)
#ciphertext = cipher.iv + cipher.encrypt(pad(b"flag!", cipher.block_size))
#print(f"TASK: {ciphertext.hex()}")

pd = process("/challenge/dispatcher") # Dispatcher Process
pw = process("/challenge/worker") # Worker Process

dl = pd.recvline().strip().decode() # receive a Dispatcher Line
payload = bytes.fromhex(dl.split()[1])

iv = payload[:16]
tamper = strxor(pad(b'flag!', 16), pad(b'sleep', 16))
tamper = strxor(tamper, iv)


tampered = "TASK: " + (tamper + payload[16:]).hex()

pw.sendline(tampered) # Send line to Process Worker

while wl := pw.recvline().strip().decode():
    if len(wl) < 1:
        break
    print(wl)
```
