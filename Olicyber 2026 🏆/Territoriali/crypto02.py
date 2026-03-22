# from pwn import *

# r = remote("10.45.1.2", 10927)

# s = b''
# for i in range(100):
#     r.recvuntil(b'! ')
#     s += r.recvline()
#     r.sendlineafter(b'> ', b'si')

# open("palle.txt", "wb").write(s)

def xor(a,b):
    return bytes(x ^ y for x, y in zip(a, b))

f = open("palle.txt").readlines()
f = [bytes.fromhex(i.strip()) for i in f]

import string
alph = (string.ascii_letters + string.digits + "+/").encode()
flag = ''
for i in range(len(f[0])):
    for c in alph:
        if all(xor(bytes([a[i]]), bytes([c])) in alph for a in f):
            flag += bytes([c]).decode()
            print(flag)