# Problem Statement
The previous challenge had you decrypting a partial block by abusing the padding at the end. But what happens if the block is "full", as in, 16-bytes long? Let's explore an example with the plaintext AAAABBBBCCCCDDDD, which is 16 bytes long! As you recall, PKCS7 adds a whole block of padding in this scenario! What we would see after padding is:
Plaintext Block 1 	Plaintext Block 2 (oops, just padding!)
AAAABBBBCCCCDDDD 	\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10

When encrypted, we'd end up with three blocks:
Ciphertext Block 1 	Ciphertext Block 2 	Ciphertext Block 3
IV 	Encrypted AAAABBBBCCCCDDDD 	Encrypted Padding

If you know that the plaintext length is aligned to the block length like in the above example, you already know the plaintext of the last block (it's just the padding!). Once you know it's all just padding, you can discard it and start attacking the next-to-last block (in this example, Ciphertext Block 2)! You'd try tampering with the last byte of the plaintext (by messing with the IV that gets XORed into it) until you got a successful padding, then use that to recover (and be able to control) the last byte, then go from there. The same POA attack, but against the second-to-last block when the last block is all padding!


## Observations
- We could just totally reuse the code from the previous challenge and ignore the last 16 bytes of the ciphertext. I just made a few steps towards processing multiple blocks to build towards the next challenge.
- The last block isn't properly decoded since it's still XOR'd with the IV by recycling the code from the previous challenge.
  - Since we know it's all padding, it doesn't really matter, so I didn't bother adjust it. The code for the next challenge has those changes properly done.
  


# Solution
```
#!/opt/pwn.college/python

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

BLOCKSIZE = 16

#key = open("/challenge/.key", "rb").read()
#cipher = AES.new(key=key, mode=AES.MODE_CBC)
#ciphertext = cipher.iv + cipher.encrypt(pad(b"flag!", cipher.block_size))

#print(f"TASK: {ciphertext.hex()}")

pd = process(["/challenge/dispatcher", "pw"]) 
pw = process("/challenge/worker")
dl = pd.recvline().strip().decode()
print(f"\tReceived: {dl}")
payload = bytes.fromhex(dl.split()[1])

wl = pw.recvline().strip().decode()
pw_length = int(wl.split("is ")[1].split(" bytes")[0])
print(f"Password is: {pw_length} bytes long")

iv_original = payload[:BLOCKSIZE]
ciphertext_blocks = payload[BLOCKSIZE:]
# split the ciphertext into a list of BLOCKSIZE length blocks
ciphertext_blocks = [payload[block : block + BLOCKSIZE] for block in range(0, len(ciphertext_blocks), BLOCKSIZE)]
plaintext_block = bytearray(BLOCKSIZE)
intermediate_block = bytearray(BLOCKSIZE) 


def padding_oracle_attack(ciphertext_block):
    index = BLOCKSIZE - 1
    iv = bytearray(BLOCKSIZE)
    while index >= 0:
        print(f"\n===================\nProcessing byte {index}\n====================")
        pad_value = BLOCKSIZE - index
        for guess in range(256):
            # iv = iv_block # TODO: Check if should replace intermediate Bytes to right
            iv[index] = guess
            for i in range(index + 1, BLOCKSIZE):
                iv[i] = intermediate_block[i] ^ pad_value
            
            task = b'TASK: ' + (iv + ciphertext_block).hex().encode()
            pw.sendline(task)
            wl = pw.recvline().strip().decode()
            
            if "Error: " not in wl:
                print(f"\n\t**** FOUND BYTE {index}: {guess}")
                print(f"\n\tSent: {task}\n\tGot: {wl}") 
                intermediate_block[index] = guess ^ pad_value
                plaintext_block[index] = intermediate_block[index] ^ iv_original[index]
                break

        index -= 1
    return plaintext_block

for block in ciphertext_blocks:
    plaintext_block = padding_oracle_attack(block)
    print(f"\n\t******* OUTPUT:\n{plaintext_block}")

sol = process("/challenge/redeem")
sol.sendlineafter("Password? ", plaintext_block[:pw_length])
print(sol.recvall().decode())

```
