# Problem Statement
Let's put the last two challenges together. The previous challenges had just one ciphertext block, whether it started like that or you quickly got there by discarding the all-padding block. Thus, you were able to mess with that block's plaintext by chaining up the IV.

This level encrypts the actual flag, and thus has multiple blocks that actually have data. Keep in mind that to mess with the decryption of block N, you must modify ciphertext N-1. For the first block, this is the IV, but not for the rest!

This is one of the hardest challenges in this module, but you can get your head around if you take it step by step. So, what are you waiting for? Go recover the flag!

## Observations
- Still same code from the previous challenges, just resetting the intermediate, plaintext and "guessing" block (previously, `iv`)
  - These probably don't need to be reset since we process a byte at a time from right to left
- I left all the intermediate output in there so it's a bit messy, but the plaintext is fully displayed at the end.

## Solution
```
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

BLOCKSIZE = 16

pd = process(["/challenge/dispatcher", "flag"]) 
pw = process("/challenge/worker")
dl = pd.recvline().strip().decode()
print(f"\tReceived: {dl}")
payload = bytes.fromhex(dl.split()[1])

ciphertext_blocks = [payload[block : block + BLOCKSIZE] for block in range(0, len(payload), BLOCKSIZE)]


def padding_oracle_attack(current_block, previous_block):
    index = BLOCKSIZE - 1
    plaintext_block = bytearray(BLOCKSIZE)
    guessing_block = bytearray(BLOCKSIZE)
    intermediate_block = bytearray(BLOCKSIZE) 
    while index >= 0:
        print(f"\n===================\nProcessing byte {index}\n====================")
        pad_value = BLOCKSIZE - index
        for guess in range(256):
            # iv = iv_block # TODO: Check if should replace intermediate Bytes to right
            guessing_block[index] = guess
            for i in range(index + 1, BLOCKSIZE):
                guessing_block[i] = intermediate_block[i] ^ pad_value
            
            task = b'TASK: ' + (guessing_block + current_block).hex().encode()
            pw.sendline(task)
            wl = pw.recvline().strip().decode()
            
            if "Error: " not in wl:
                print(f"\n\t**** FOUND BYTE {index}: {guess}")
                print(f"\n\tSent: {task}\n\tGot: {wl}") 
                intermediate_block[index] = guess ^ pad_value
                plaintext_block[index] = intermediate_block[index] ^ previous_block[index]
                break

        index -= 1
    return plaintext_block

output_string = b""
print(f"Decrypting: {ciphertext_blocks}")
for i in range(1, len(ciphertext_blocks)): # don't process the IV as a current block to guess, start at index 1
    print(f"Starting decryption: \n\t{ciphertext_blocks[i]}  - {ciphertext_blocks[i-1]}")
    plaintext_block = padding_oracle_attack(ciphertext_blocks[i], ciphertext_blocks[i-1])
    print(f"\n\t******* OUTPUT:\n{plaintext_block}")
    output_string += plaintext_block

print(f"\n\n Full plaintext: {output_string}")
```
