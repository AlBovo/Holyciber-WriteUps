#!/usr/bin/env python3
from pwn import *

r = remote("camh.challs.olicyber.it", 30995)

s = [0x243, 0xf6a, 0x888, 0x5a3]

buf0 = 0

for i in range(4):
    buf0 <<= 12
    buf0 |= s[i]

buf0 = buf0.to_bytes(6, "big")

buf1 = buf0 + bytes.fromhex('00' * (6 * 5))
buf2 = buf0 + bytes.fromhex('00' * (6 * 4))


def SmallCubeHash(m: bytes):
    def rot_left(word, k, n_bits = 12):
        return (word << k) & (2**n_bits - 1) | (word >> (n_bits - k))

    x = [0x243, 0xf6a, 0x888, 0x5a3]
    R = [7, 11]
    b = 6
    f = 24
    mask = 0xfff

    m += b"\x80"
    m += b"\x00" * (-len(m) % b)

    for i in range(0, len(m), b):
        block = int.from_bytes(m[i:i+b], "big")
        x[0] ^= ((block >> 36) & mask)
        x[1] ^= ((block >> 24) & mask)
        x[2] ^= ((block >> 12) & mask)
        x[3] ^= (block & mask)
        # print("1: x =", x)

        for _ in range(f):
            for j in range(2):
                x[2] = (x[2] + x[0]) & mask
                x[3] = (x[3] + x[1]) & mask
                x[0] = rot_left(x[0], R[j])
                x[1] = rot_left(x[1], R[j])
                x[0], x[1] = x[1], x[0]
                x[0] ^= x[2]
                x[1] ^= x[3]
                x[2], x[3] = x[3], x[2]
        # print("2: x =", x)

    output = (x[0] << 36) | (x[1] << 24) | (x[2] << 12) | x[3]

    return output.to_bytes(6, "big")

def xor(a,b):
    return bytes([x^y for x,y in zip(a,b)])

def CAMH(m, k):
    opad = b"\x5c"*len(k)
    ipad = b"\x36"*len(k)

    return SmallCubeHash(SmallCubeHash(m + xor(k, ipad)) + xor(k, opad))

k = os.urandom(32)

print("CAMH(buf1, k) = ", CAMH(buf1, k).hex())
print("CAMH(buf2, k) = ", CAMH(buf2, k).hex())

r.sendlineafter(b': ', buf1.hex().encode())
r.sendlineafter(b': ', buf2.hex().encode())
r.recvuntil(b': ')
print(r.recvline().strip().decode())