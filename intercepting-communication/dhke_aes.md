# Problem Statement

## Observations
This one is pretty straightforward, just a nice to have OOP implementation to interact with if the next challenges have a similar format

# Solution
```
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random.random import getrandbits
from pwn import *


class DHKE_AES:
    def __init__(self, p, g, A):
        # deliberately ignoring checks for small subgroups (p = 2q+1; a and b coprime with p and g) and randomness of exponents p and g
        self.p = p
        self.g = g
        self.A = A
        self.b = getrandbits(2048) # minimum recommended size
        self.B = self._gen_B()
        self.s = self._DHKE()
        self.BLOCKSIZE = 16
        self.key = None
        self.iv = None
        self.cipher = None

        
    def _gen_B(self):
        return pow(self.g, self.b, self.p)

    def _DHKE(self):    
        return pow(self.A, self.b, self.p)
    
    def decrypt(self, ciphertext):
        self.key = self.s.to_bytes(256, "little")[:self.BLOCKSIZE]
        self.iv = ciphertext[:self.BLOCKSIZE]
        self.cipher = AES.new(key=self.key, mode=AES.MODE_CBC, iv=self.iv)
        return unpad(self.cipher.decrypt(ciphertext), self.BLOCKSIZE)


p = process("/challenge/run")

dh_params = p.recvuntil(b"B? ").decode("utf-8")
dh_p = int(dh_params.split("p = ")[1].split("g = ")[0].strip(), 16)
dh_g = int(dh_params.split("g = ")[1].split("A = ")[0].strip(), 16)
dh_A = int(dh_params.split("A = ")[1].split("B?")[0].strip(), 16)

dhke_aes = DHKE_AES(dh_p, dh_g, dh_A)
p.sendline(f'{dhke_aes.B:x}'.encode("utf-8")) # the `:x` format specifier returns the int in hex format without the `0x` prefix, as the challenge expects.


ciphertext = bytes.fromhex(p.recvline().split(b"(hex): ")[1].strip().decode("utf-8"))

print(dhke_aes.decrypt(ciphertext))
```
