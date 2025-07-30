# Problem Statement
The previous challenge ignored something very important: padding. AES has a 128-bit (16 byte) block size. This means that input to the algorithm must be 16 bytes long, and any input shorter than that must be padded to 16 bytes by having data added to the plaintext before encryption. When the ciphertext is decrypted, the result must be unpadded (e.g., the added padding bytes must be removed) to recover the original plaintext.

How to pad is an interesting question. For example, you could pad with null bytes (0x00). But what if your data has null bytes at the end? They might be erroneously removed during unpadding, leaving you with a plaintext different than your original! This would not be good.

One padding standard (and likely the most popular) is PKCS7, which simply pads the input with bytes all containing a value equal to the number of bytes padded. If one byte is added to a 15-byte input, it contains the value 0x01, two bytes added to a 14-byte input would be 0x02 0x02, and the 15 bytes added to a 1-byte input would all have a value 0x0f. During unpadding, PKCS7 looks at the value of the last byte of the block and removes that many bytes. Simple!

But wait... What if exactly 16 bytes of plaintext are encrypted (e.g., no padding needed), but the plaintext byte has a value of 0x01? Left to its own devices, PKCS7 would chop off that byte during unpadding, leaving us with a corrupted plaintext. The solution to this is slightly silly: if the last block of the plaintext is exactly 16 bytes, we add a block of all padding (e.g., 16 padding bytes, each with a value of 0x10). PKCS7 removes the whole block during unpadding, and the sanctity of the plaintext is preserved at the expense of a bit more data.

Anyways, the previous challenge explicitly disabled this last case, which would have the result of popping in a "decoy" ciphertext block full of padding as you tried to push the very first suffix byte to its own block. This challenge pads properly. Watch out for that "decoy" block, and go solve it!

NOTE: The full-padding block will only appear when the last block of plaintext perfectly fills 16 bytes. It'll vanish when one more byte is appended (replaced with the padded new block containing the last byte of plaintext), but will reappear when the new block reaches 16 bytes in length.

# Observations
- This should be straightforward after solving the previous one. We just have to add padding as described in the challenge descritpion for our first 15 guesses
- However, the interesting point here is that the program will break when you guess the 6th character (from the end)
  - The padding for 6 characters in the last block becomes (16 - 6) = 10 -> [0x0A] * 15, which happens to be 10 newline chars (`\n`)
  - The program will break at this point. I tried a lot of combinations with sendline, send, sendlineafter, etc. And I got lazy and chose to just guess 2 characters at a time to skip that padding

If anybody reads this (doubt) and finds a better solution, please let me know!!!

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
    return p.readline().decode().split("Result: ")[1].strip()

def split_chunks_list(ct, n=block_text_size): # n = block size * 2 (1B -> 2 hex chars)
    return [ct[i:i+n] for i in range(0, len(ct), n)]

# Generate a dictionary for efficient lookup by block value
def split_chunks_dict(ct, n=block_text_size): # n = block size * 2 (1B -> 2 hex chars)
    return {ct[i:i+n] : True for i in range(0, len(ct), n)}

def get_original_blocks():
    return append_data(b'') # append nothing, just get the original flag encrypted as ciphertext

def append_data(data, dictionary = True):
    p.sendlineafter("Choice? ", b"2") # Append to flag
    p.sendlineafter("Data? ", data) 
    ct_chunks = split_chunks_dict(get_result()) if dictionary else split_chunks_list(get_result())
    return ct_chunks

# In this case, padding only applies if we have guessed 15 or less characters. Otherwise, padding is applied only in the last block and we don't care anymore about that.
def choose_plaintext(data, dictionary = True, padding = False):
    # Apply PKCS7 padding efficiently (avoiding loops) 
    pad = b''
    if padding:
        pad_len = -(len(data) - BLOCKSIZE) # this is hacky, only if you know you won't encode 16 or more chars. Otherwise, use proper modular arithmetic and handle the case where the data has BLOCKSIZE length with an extra padding block of 0x(BLOCKSIZE) * BLOCKSIZE
        if pad_len > 0: 
            pad = bytes([pad_len] * pad_len)
    p.sendlineafter("Choice? ", b"1") # Append to flag
    if(padding and pad_len == 10): print(f"choose_plaintext(): Sending {data+pad}")
    p.sendlineafter("Data? ", data + pad)
    ct_chunks = split_chunks_dict(get_result()) if dictionary else split_chunks_list(get_result())
    return ct_chunks

def calc_pt_length(n=block_text_size): # n = block size * 2 (1B -> 2 hex chars)
    canary = b'}' + b'\x0F' * 15 # our chosen plaintext to know we have shifted the pt enough to add a new block, taking PKCS7 into account
    chosen_plaintext = choose_plaintext(canary, dictionary=False)[0]
    ct_chunks = {} # use a dictionary to index by chunk results for efficient lookup
    
    # Keep shifting the flag by 1 character at a time until we see the last block match our chosen input
    offset = 0
    while chosen_plaintext not in ct_chunks:
        offset += 1
        flag_shifter = b'A' * offset
        ct_chunks = append_data(flag_shifter)#split_chunks_dict(get_result())
    
    # At this point, we know there's (offset - 1) padding bytes and an extra block
    # so the flag is (block_size * (blocks - 1)) - (offset - 1)  bytes long.
    # We have n = 32 for the hex encoding, but the block size by default is actually 16
    plaintext_length = int((n/2) * (len(ct_chunks) - 1) - offset + 1)
    #lookup_table[plaintext_length - 1] = '}'
    return plaintext_length 

# If we guess the char at position 6 from the bottom, we have 10 bytes to pad
# PKCS7 would require \x0A ten times to pad this, but \x0A == \n, and it breaks
# So we will have to make a guess of 2 bytes at a time (65536 instead of 256 guesses this time, although to be fair we reduce the search space to a subset of printable ASCII).
def guess_2_at_a_time(plaintext, offset):
    prefix = b'A' * offset # append as many A's as required to shift the next target character
    next_target_blocks = append_data(prefix, dictionary=False)
    # The next block to guide our guess is the last block we haven't completely guessed
    next_target_block = next_target_blocks[-1] # this is a special case where we always want last block
    for char1 in range(start, end + 1):
        for char2 in range(start, end + 1):
            guess = (chr(char1) + chr(char2) + plaintext).encode()
            next_block_guess = choose_plaintext(guess, dictionary=False, padding = True)[0]
            if next_block_guess == next_target_block:
                print(f"\n\t**** DOUBLE GUESS: Guessed : {chr(char1) + chr(char2)}")
                return chr(char1) + chr(char2)
    return ''

original_block_amount = len(get_original_blocks())
pt_len = calc_pt_length() # length of original plaintext (flag)
padding_bytes_amount = BLOCKSIZE * original_block_amount - pt_len 
offset = padding_bytes_amount + 1 # this offset isolates the last original flag char in the last block
sliding_string = "" # initialize our 16-char 'sliding string' to choose plaintext

flag = "}"
while flag[:1] != '{':
    offset += 1 # increment right away, we don't need to guess the last char ('}')
    complete_blocks = int(len(flag) / BLOCKSIZE) # How many complete blocks from the end we have gathered
    prefix = b'A' * offset # append as many A's as required to shift the next target character
    next_target_blocks = append_data(prefix, dictionary=False)
    # The next block to guide our guess is the last block we haven't completely guessed
    next_target_block_index = len(next_target_blocks) - 1 - complete_blocks 
    
    # check if the last block is full padding
    full_padding_block = (pt_len + offset) % BLOCKSIZE == 0
    if full_padding_block: next_target_block_index -= 1 # ignore the last block
    # Select target block
    next_target_block = next_target_blocks[next_target_block_index]
    

    # Update our sliding string to generate exactly one block with our guess + next 0-15 guessed chars
    sliding_string = flag[0:BLOCKSIZE] # get (at most) the first 16 chars of the flag we have so far

    if len(flag) == 5: # if we are guessing the 6th char from the end, guess 2 at a time to avoid padding with \n characters (0x0A)
        offset += 1 # manually increment an extra time the offset since we guessed 2 chars
        print("\n*******\nGOING INTO DOUBLEGUESS\n******\n")
        double_guess = guess_2_at_a_time(sliding_string, offset)
        if len(double_guess):
            flag = double_guess + flag
            continue
    
    for char in range(start, end+1):
        guess = (chr(char) + sliding_string).encode()

        next_block_guess = choose_plaintext(guess, dictionary=False, padding = len(flag) < 16)[0]
        if next_block_guess == next_target_block:
            flag = chr(char) + flag
            print(f"Guessed so far: {flag}, offset was {offset}")
            break

print(flag)
```
