# Problem Statement
Okay, now let's complicate things slightly. It's not so common that you can just chop off the end of interesting data and go wild. However, much more common is the ability to prepend chosen plaintext to a secret before it's encrypted. If you carefully craft the prepended data so that it pushes the end of the secret into a new block, you've just successfully isolated it, accomplishing the same as if you were chopping it off!

Go ahead and do that in this challenge. The core attack is the same as before, it just involves more data massaging.

HINT: Keep in mind that a typical pwn.college flag is somewhere upwards of 50 bytes long. This is four blocks (three full and one partial), and the length can vary slightly. You will need to experiment with how many bytes you must prepend to push even one of the end characters to its own block.

HINT: Keep in mind that blocks are 16 bytes long! After you leak the last 16 bytes, you'll be looking at the second-to-last block, and so on.

# Observations
- This is just a more complex scenario for the suffix problem: We use specific-length prefixes to expose the suffix we are interested in.
- The first step I actually took was manually checking how many characters were required to create an extra block, which tells us how much padding there was in the last block and therefore the flag length.
  - I wanted to solve the general case, so I abstracted that reasoning into a function for any length plaintext.

# Solution
## Concept
* In the pics below, dark green is prefix we add; light green is padding; light blue is the original flag; brown is what we have guessed; yellow is the next guess.
- First step, we find how much padding there was and we add one. That's how many characters we need to prefix to isolate the last char and match against chosen plaintext.
  - <img width="1784" height="199" alt="image" src="https://github.com/user-attachments/assets/8b906b65-5655-4996-bfd6-e36567d5c829" />
- Next, we have to isolate the previous character. Since we can't really isolate it, we have to isolate that one + what we already know.
  - Until we fill up the last block, we can keep just adding length to the prefix and keep comparing our chosen plaintext encrypted vs the last encrypted block.
  - Once we have filled at least a block at the end, we need to move to the previous one but still leave 15 characters we have guessed correctly to form our chosen plaintext. The last block will be the first char we guessed, `}`, and padding.
  - <img width="1130" height="380" alt="image" src="https://github.com/user-attachments/assets/b7913a00-8960-4257-9b0e-76156a2cd41a" />

## Code
```
from pwn import *

# This problem can be transformed into the suffix problem.
# We just need to know the length of the pt and isolate a block with our next guess at a time.

p = process("/challenge/run")

start = 33 # beginning of printable ASCII chars
end = 126 # end of printable ASCII chars

BLOCKSIZE = 16 # This is the default block size in AES CBC
block_text_size = BLOCKSIZE * 2

def get_result():
    return p.readline().decode().split("Result: ")[1].strip()

def split_chunks_list(ct, n=block_text_size): # n = block size * 2 (1B -> 2 hex chars)
    return [ct[i:i+n] for i in range(0, len(ct), n)]

# Generate a dictionary for efficient lookup by block value
def split_chunks_dict(ct, n=block_text_size): # n = block size * 2 (1B -> 2 hex chars)
    return {ct[i:i+n] : True for i in range(0, len(ct), n)}

def get_original_blocks():
    return append_data('') # append nothing, just get the original flag encrypted as ciphertext

def append_data(data, dictionary = True):
    p.sendlineafter("Choice? ", b"2") # Append to flag
    p.sendlineafter("Data? ", data.encode()) 
    ct_chunks = split_chunks_dict(get_result()) if dictionary else split_chunks_list(get_result())
    return ct_chunks

def choose_plaintext(data, dictionary = True):
    p.sendlineafter("Choice? ", b"1") # Append to flag
    p.sendlineafter("Data? ", data.encode()) 
    ct_chunks = split_chunks_dict(get_result()) if dictionary else split_chunks_list(get_result())
    return ct_chunks

def calc_pt_length(n=block_text_size): # n = block size * 2 (1B -> 2 hex chars)
    canary = "}" # our chosen plaintext to know we have shifted the pt enough to add a new block
    chosen_plaintext = choose_plaintext(canary, dictionary=False)[0]
    ct_chunks = {} # use a dictionary to index by chunk results for efficient lookup
    
    # Keep shifting the flag by 1 character at a time until we see the last block match our chosen input
    offset = 0
    while chosen_plaintext not in ct_chunks:
        offset += 1
        flag_shifter = 'A' * offset
        ct_chunks = append_data(flag_shifter)#split_chunks_dict(get_result())
    
    # At this point, we know there's (offset - 1) padding bytes and an extra block
    # so the flag is (block_size * (blocks - 1)) - (offset - 1)  bytes long.
    # We have n = 32 for the hex encoding, but the block size by default is actually 16
    plaintext_length = int((n/2) * (len(ct_chunks) - 1) - offset + 1)
    #lookup_table[plaintext_length - 1] = '}'
    return plaintext_length 

original_block_amount = len(get_original_blocks())
pt_len = calc_pt_length() # length of original plaintext (flag)
padding_bytes_amount = BLOCKSIZE * original_block_amount - pt_len 
offset = padding_bytes_amount + 1 # this offset isolates the last original flag char in the last block
sliding_string = "" # initialize our 16-char 'sliding string' to choose plaintext


flag = "}"
while flag[:1] != '{':
    offset += 1 # increment right away, we don't need to guess the last char ('}')
    complete_blocks = int(len(flag) / BLOCKSIZE) # How many complete blocks from the end we have gathered
    prefix = "A" * offset # append as many A's as required to shift the next target character
    next_target_blocks = append_data(prefix, dictionary=False)
    
    # The next block to guide our guess is the last block we haven't completely guessed
    next_target_block_index = len(next_target_blocks) - 1 - complete_blocks 
    next_target_block = next_target_blocks[next_target_block_index]

    # Update our sliding string to generate exactly one block with our guess + next 0-15 guessed chars
    sliding_string = flag[0:BLOCKSIZE] # get (at most) the first 16 chars of the flag we have so far

    for char in range(start, end+1):  
        next_block_guess = choose_plaintext(chr(char) + sliding_string, dictionary=False)[0]
        if next_block_guess == next_target_block:
            print(f"Guessed so far: {flag}")
            flag = chr(char) + flag
            break

print(flag)
```
