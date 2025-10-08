# Problem Statement
So you can manipulate the padding... If you messed up somewhere along the lines of the previous challenge and created an invalid padding, you might have noticed that the worker crashed with an error about the padding being incorrect!

It turns out that this one crash completely breaks the Confidentiality of the AES-CBC cryptosystem, allowing attackers to decrypt messages without having the key. Let's dig in...

Recall that PKCS7 padding adds N bytes with the value N, so if 11 bytes of padding were added, they have the value 0x0b. During unpadding, PKCS7 will read the value N of the last byte, make sure that the last N bytes (including that last byte) have that same value, and remove those bytes. If the value N is bigger than the block size, or the bytes don't all have the value N, most implementations of PKCS7, including the one provided by PyCryptoDome, will error.

Consider how careful you had to be in the previous level with the padding, and how this required you to know the letter you wanted to remove. What if you didn't know that letter? Your random guesses at what to XOR it with would cause an error 255 times out of 256 (as long as you handled the rest of the padding properly, of course), and the one time it did not, by known what the final padding had to be and what your XOR value was, you can recover the letter value! This is called a Padding Oracle Attack, after the "oracle" (error) that tells you if your padding was correct!

Of course, once you remove (and learn) the last byte of the plaintext, the second-to-last byte becomes the last byte, and you can attack it!

So, what are you waiting for? Go recover the flag!

FUN FACT: The only way to prevent a Padding Oracle Attack is to avoid having a Padding Oracle. Depending on the application, this can be surprisingly tricky: a failure state is hard to mask completely from the user/attacker of the application, and for some applications, the padding failure is the only source of an error state! Moreover, even if the error itself is hidden from the user/attacker, it's often inferable indirectly (e.g., by detecting timing differences between the padding error and padding success cases).

RESOURCES: You might find some animated/interactive POA demonstrations useful:

    An Animated Primer from CryptoPals
    Another Animated Primer
    An Interactive POA Explorer




## Observations
- All we need is the resource provided: https://dylanpindur.com/blog/padding-oracles-an-animated-primer/
  - Particularly, this slide:
    <img width="823" height="472" alt="image" src="https://github.com/user-attachments/assets/e1f70930-8f93-4aa1-b4fd-80dd8c461b3a" />

- Make sure you receive the first output line from `/challenge/worker` before the guessing loop. Otherwise, it will seem like the first guess for the last byte, `\x00`, succeeded, and you'll never find the password.
- If it doesn't work - I did not take care of the edge case where the original padding actually happens to be 2 bytes and the first right guess is the one that makes the decoded ciphertext be `\x02` instead of `\x01`. I think it's easier to play the odds and re-start the challenge if it doesn't work than adding the extra logic. You would have to keep track of the first guess and, if no successful guess is found for the second-to-last byte, or the password ends up being wrong, restart the loop and skip the saved first guess for the last byte.

# Solution
```
#!/opt/pwn.college/python

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor

BLOCKSIZE = 16

#########################################
#### /challenge/dispatcher relevant content for formatting: ####
#########################################
#### key = open("/challenge/.key", "rb").read()
#### cipher = AES.new(key=key, mode=AES.MODE_CBC)
#### ciphertext = cipher.iv + cipher.encrypt(pad(b"flag!", cipher.block_size))
#### print(f"TASK: {ciphertext.hex()}")

pd = process(["/challenge/dispatcher", "pw"]) 
pw = process("/challenge/worker")
dl = pd.recvline().strip().decode()
print(f"\tReceived: {dl}")
payload = bytes.fromhex(dl.split()[1])

wl = pw.recvline().strip().decode() # RECEIVE THIS OUTSIDE THE LOOP, WHETHER YOU USE IT OR NOT
pw_length = int(wl.split("is ")[1].split(" bytes")[0])
print(f"Password is: {pw_length} bytes long")

iv_original = payload[:BLOCKSIZE]
ciphertext_block = payload[BLOCKSIZE:]
plaintext_block = bytearray(BLOCKSIZE)
intermediate_block = bytearray(BLOCKSIZE) 


def padding_oracle_attack():
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

padding_oracle_attack()


sol = process("/challenge/redeem")
sol.sendlineafter("Password? ", plaintext_block[:pw_length])
print(sol.recvall().decode())
```
