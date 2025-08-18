# Problem Statement
This is the miniboss of AES-ECB-CPA. You don't get an easy way to build your codebook anymore: you must build it in the prefix. 
If you pad your own prefixed data yourself, you can control entire blocks, and that's all you need! Other than that, the attack remains the same. Good luck!

## Notes
- So this can still be approached just like the prefix case, but we have to isolate the flag blocks way more carefully. The general algorithm is as follows:
  - Find out the original plaintext length and how many blocks are returned when appenidng an empty string -> by adding dummy prefixes until there's a new block
  - Use that dummy prefix as a starting point to add one more byte and isolate the last character -> Last block will be last character + 15 padding chars (0xF)
  - Keep adding byte by byte to that dummy prefix and guessing one more char in front of the prefix, adjusting the padding.
  - Once we have guessed a full block, we keep increasing the dummy prefix but we stop padding the guess that precedes it - since we don't look at the last block anymore.

The only easy way I found to wrap my head around how this works in order to build the guessing algorithm was to make a drawing:
<img width="995" height="754" alt="image" src="https://github.com/user-attachments/assets/eb1bc70a-4411-4e0f-9b5a-e59bf9fb1387" />


# Solution
```
from pwn import *

# This problem can be transformed into the suffix problem.
# We just need to know the length of the pt and isolate a block with our next guess at a time.

p = process("/challenge/run")

start = 45#33 # beginning of printable ASCII chars
end = 126 # end of printable ASCII chars

BLOCKSIZE = 16 # This is the default block size in AES CBC
block_text_size = BLOCKSIZE * 2

def get_result():
    return p.readline().decode().split("Ciphertext: ")[1].strip()

def split_chunks_list(ct, n=block_text_size): # n = block size * 2 (1B -> 2 hex chars)
    return [ct[i:i+n] for i in range(0, len(ct), n)]

# Generate a dictionary for efficient lookup by block value
def split_chunks_dict(ct, n=block_text_size): # n = block size * 2 (1B -> 2 hex chars)
    return {ct[i:i+n] : True for i in range(0, len(ct), n)}

def get_original_blocks():
    return append_data(b'') # append nothing, just get the original flag encrypted as ciphertext

def append_data(data, dictionary = True):
    p.sendlineafter("Data? ", data.hex())
    ct_chunks = split_chunks_dict(get_result()) if dictionary else split_chunks_list(get_result())
    return ct_chunks

# PKCS7 padding
def pad_data(data):
    padding_len = BLOCKSIZE - (len(data) % BLOCKSIZE)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def calc_pt_length(n=block_text_size): # n = block size * 2 (1B -> 2 hex chars)
    original_blocks_length = len(get_original_blocks())
    prefix = b'\x00'
    i = 1
    while len(append_data(prefix * i)) == original_blocks_length:
        i+= 1
    
    return BLOCKSIZE * original_blocks_length - i 



original_block_amount = len(get_original_blocks())
pt_len = calc_pt_length() # length of original plaintext (flag)


padding_bytes_amount = BLOCKSIZE * original_block_amount - pt_len 
offset = padding_bytes_amount # this offset for padding completes the input to BLOCKSIZE length. The next will isolate the last char of the flag `{` in the last block - with padding.
sliding_string = "" # initialize our 16-char 'sliding string' to choose plaintext
prefix = b'\x00' * offset
flag = ""

while flag[:1] != '{':

    offset += 1
    complete_blocks = int(len(flag) / BLOCKSIZE) # How many complete blocks from the end we have gathered, this tells us which block is our chosen plaintext

    for char in range(start, end+1):
        guess = (chr(char) + flag).encode()
        
        # We only need to pad data until we guess a full block
        if len(flag) < BLOCKSIZE:
            guess = pad_data(guess)
        elif len(flag) >= BLOCKSIZE:
            guess = guess[:BLOCKSIZE]

        prefix = b'\x00' * offset
        guess += prefix
        
        next_target_blocks = append_data(guess, dictionary=False)
        # We always look at the last block to compare our guess -- unless it's all padding 
        next_target_block_index = len(next_target_blocks) - 1 - complete_blocks

        if (len(flag) + 1) % BLOCKSIZE == 0: # if next guess (minus padding) is a full block
            next_target_block_index -= 1 # the last block is just padding
        
        # check if the last block is full padding
        # Select target block
        next_target_block = next_target_blocks[next_target_block_index]

        # Our chosen plaintext will be in the first block always
        next_block_guess = next_target_blocks[0]
         
        if next_block_guess == next_target_block:
            bool_guess = True
            flag = chr(char) + flag
            print(f"Guessed so far: {flag}")
            break 
            
print(flag)

```
