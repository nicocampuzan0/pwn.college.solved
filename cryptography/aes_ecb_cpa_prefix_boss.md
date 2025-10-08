# Problem Statement
Okay, time for the AES-ECB-CPA final boss! Can you carry out this attack against an encrypted secret storage web server? Let's find out!

## Observations
- Still similar concept as the couple of previous ones, just need to adjust the DB R/W and Delete operations as well as base 64 decoding
- Don't really worry about the `|` between each DB row -  it just means we need a few more iterations on average to guess each block unless we adjust for it, and we waste cycles initially to find the right offset
  - It took more time for me to adjust for this than to just bruteforce it with a few wasted cycles per guess, so I just went with the bruteforce approach.


# Solution
```
#!/opt/pwn.college/python

from pwn import *
import requests
from base64 import b64encode, b64decode

start = 45
end =126

BLOCKSIZE = 16
block_text_size = BLOCKSIZE * 2


def strip_result(text):
    return text.split("<pre>")[1].split("</pre>")[0]

def get_blocks():
    ct = strip_result(requests.get("http://challenge.localhost/").text)
    ct = b64decode(ct)
    return [ct[i:i+BLOCKSIZE] for i in range(0, len(ct), BLOCKSIZE)]

def get_original_blocks():
    reset_db()
    return get_blocks()

def append_data(data):
    requests.post("http://challenge.localhost/", data={'content': data})

def append_and_read(data):
    append_data(data)
    return get_blocks()

def reset_db():
    requests.post("http://challenge.localhost/reset")


def calc_pt_length(n=block_text_size): # n = block size * 2 (1B -> 2 hex chars)
    original_blocks_length = len(get_original_blocks())
    prefix = b'\x00'
    i = 1
    while len(append_and_read(prefix * i)) == original_blocks_length:
        i+= 1
    
    return BLOCKSIZE * original_blocks_length - i

def pad_data(data):
    padding_len = BLOCKSIZE - (len(data) % BLOCKSIZE)
    padding = bytes([padding_len] * padding_len)
    return data + padding


offset = 0 # this offset for padding completes the input to BLOCKSIZE length. The next will isolate the last char of the flag `{` in the last block - with padding.
sliding_string = "" # initialize our 16-char 'sliding string' to choose plaintext
prefix = b'\x00' * offset
flag = ""

while flag[:1] != '{':
    if (len(flag) + 10 < offset):
        break
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
        next_target_blocks = append_and_read(guess)
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
        else:

            reset_db()    

print(flag)

```
