#!/usr/bin/env python3
from Crypto.Cipher import AES
from hashlib import sha256
from tqdm import tqdm
from pwn import *

def expand_pin(pin):
    return sha256(pin).digest()[:16]

k1, k2 = b"", b""

k1s, a = {}, []
for i in tqdm(range(1000000)):
    pin = str(i).zfill(6).encode()
    c1 = AES.new(expand_pin(pin), AES.MODE_ECB)
    a.append(c1.decrypt(b'gabibbo_hates_me').hex().encode())
    del c1

r = remote("2fapp.challs.olicyber.it", 12207)

r.recvuntil(b"\n\n")
r.sendline(b'3')
r.sendlineafter(b': ', b'admin')
r.sendlineafter(b': ', b''.join(a))
r.recvuntil(b': ')

d = bytes.fromhex(r.recvline().strip().decode())
d = [d[i:i+16] for i in range(0, len(d), 16)]

for i in tqdm(range(1000000)):
    pin = str(i).zfill(6).encode()
    c1 = AES.new(expand_pin(pin), AES.MODE_ECB)
    k1s[c1.decrypt(d[i])] = pin

for i in tqdm(range(1000000)):
    pin = str(i).zfill(6).encode()
    c2 = AES.new(expand_pin(pin), AES.MODE_ECB)
    if c2.decrypt(b'gabibbo_hates_me') in k1s:
        k1, k2 = pin, k1s[c2.decrypt(b'gabibbo_hates_me')]
        break

r.recvuntil(b"\n\n")
r.sendline(b'2')
r.recvuntil(b': ')
r.sendline(b'admin')
r.recvuntil(b': ')
r.sendline(k2)
r.recvuntil(b': ')
r.sendline(k1)
r.recvline()

flag = r.recvline()
print(flag.decode().strip())