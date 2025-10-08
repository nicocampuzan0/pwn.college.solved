# Problem Statement
You're not going to believe this, but... a Padding Oracle Attack doesn't just let you decrypt arbitrary messages: it lets you encrypt arbitrary data as well! This sounds too wild to be true, but it is. Think about it: you demonstrated the ability to modify bytes in a block by messing with the previous block's ciphertext. Unfortunately, this will make the previous block decrypt to garbage. But is that so bad? You can use a padding oracle attack to recover the exact values of this garbage, and mess with the block before that to fix this garbage plaintext to be valid data! Keep going, and you can craft fully controlled, arbitrarily long messages, all without knowing the key! When you get to the IV, just treat it as a ciphertext block (e.g., plop a fake IV in front of it and decrypt it as usual) and keep going! Incredible.

Now, you have the knowledge you need to get the flag for this challenge. Go forth and forge your message!

## Observations
- This is just an extension of the multi-block POA, with a few key differences:
  - We have to start right to left and leave the final block alone for 2 reasons:
    - The trick to control the decryption of the ciphertext is in the previous block. We don't care what the final block of icphertext is once we have figured out the corresponding intermediate block.
    - We go right to left to preserve the "XORing chain" (¯\_(ツ)_/¯) as we don't want to undo the work we did on block `i-1` when we modify it to have block `i` decrypt to whatever we choose.
  - Once we have found the intermediate bytes for each block `B(1), ... , B(n-1)`, instead of XORing them bytes with the corresponding bytes from the previous ciphertext block, we keep track of the intermediate block.
  - For each intermediate block we find, we XOR it with the corresponding plaintext block we want the ciphertext to decrypt to, and that becomes the previous ciphertext block.
    - This means we XOR cancel out the intermediate block by XORing it with itself, and then XOR that with the plaintext we want - since XOR is commutative and associative.
   
# Extension to POA Encryptoin 2
For the second POA Encryption problem added more recently, you will notice the statement mention a random plaintext, but there's no task dispatcher.
It literally means you can randomize the ciphertext, as long as it is at least as long as the required password. This gives us a ciphertext to work towards our chosen plaintext.

```
# Comment out all previous code that defines `payload` and that deals with the dispatcher process, and just add this before you define `ciphertext_blocks`
payload = get_random_bytes(password_len)
```

# Solution
```
#!/opt/pwn.college/python

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


password = pad(b"please give me the flag, kind worker process!", BLOCKSIZE)
password_len = len(password) + BLOCKSIZE # Add a block of length BLOCKSIZE to account for the IV
password_blocks = [password[block: block + BLOCKSIZE] for block in range(0, len(password), BLOCKSIZE)] # this is for convenience when XORing the intermediate blocks as we find them

print(f"payload was: {payload}, len = {len(payload)}\npassword_len = {password_len}; password={password}")
# Ensure ciphertext matches the length of the password we want
if password_len <= len(payload):
    payload = payload[:password_len]
else:
    payload = payload + get_random_bytes(password_len - len(payload))

print(f"payload now is: {payload}, len = {len(payload)}")

ciphertext_blocks = [payload[block : block + BLOCKSIZE] for block in range(0, len(payload), BLOCKSIZE)]


def padding_oracle_attack(current_block, previous_block):
    index = BLOCKSIZE - 1
    plaintext_block = bytearray(BLOCKSIZE)
    guessing_block = bytearray(BLOCKSIZE)
    intermediate_block = bytearray(BLOCKSIZE)
    while index >= 0:
#        print(f"\n===================\nProcessing byte {index}\n====================")
        pad_value = BLOCKSIZE - index
        for guess in range(256):
            guessing_block[index] = guess
            for i in range(index + 1, BLOCKSIZE):
                guessing_block[i] = intermediate_block[i] ^ pad_value
            
            task = b'TASK: ' + (guessing_block + current_block).hex().encode()
            pw.sendline(task)
            wl = pw.recvline().strip().decode()

            if "Error:" not in wl:
#                print(f"\n\t**** FOUND BYTE {index}: {guess}")
#                print(f"\n\tSent: {task}\n\tGot: {wl}")
                intermediate_block[index] = guess ^ pad_value
                plaintext_block[index] = intermediate_block[index] ^ previous_block[index]
                break

        index -= 1
    return intermediate_block 

# The tampered ciphertext that decrypts to our chosen plaintext will be computed right to left, using the intermediate blocks found XOR'd with the corresponding plaintext block
tampered_ciphertext = bytearray(payload[-BLOCKSIZE:]) # The last block remains the same, we only use it to compute the intermediate block and change the previous block.

print(f"Processing: {ciphertext_blocks} - length = {len(ciphertext_blocks)}")
                  
block_indexes = [i for i in range(1, len(ciphertext_blocks))][::-1] # create a reverse-order list with the block indexes to process right to left
for i in block_indexes:
    print(f"Computing intermediate blocks for: \n\t{ciphertext_blocks[i]}  - {ciphertext_blocks[i-1]}")
    intermediate_block = padding_oracle_attack(ciphertext_blocks[i], ciphertext_blocks[i-1])
    strxor(intermediate_block, password_blocks[i-1], intermediate_block)
    print(f"\n\t******* OUTPUT:\n{intermediate_block}")
    ciphertext_blocks[i-1] = intermediate_block # replace previous ciphertext block with tampered one to preserve the dependency chain so all blocks decrypt correctly.
    tampered_ciphertext = intermediate_block + tampered_ciphertext # prepend the intermediate block XOR'd with the password to the tampered ciphertext.

tampered_ciphertext = bytes(tampered_ciphertext)
print(f"{tampered_ciphertext.hex()} -- {len(tampered_ciphertext)}")
pw.sendline(f"TASK: {tampered_ciphertext.hex()}".encode())
while (response := pw.recvline()) is not None:
    print(response)
```
