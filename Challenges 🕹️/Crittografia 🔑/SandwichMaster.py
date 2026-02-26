#!/usr/bin/env python3
from pwn import *

r = remote("sandwichmaster.challs.olicyber.it", 30996)

msg = b'Im so good with sandwiches they call me mr Krabs'

r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'gimme m: ', b'00'*16)
r.recvuntil(b'= \'')
tag = bytes.fromhex(r.recvline()[:-2].decode())

p = b'00' * 16 + xor(msg[:16], tag[:16]).hex().encode() + msg[16:].hex().encode()
r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'gimme m: ', p)
r.recvuntil(b'= \'')
tag = bytes.fromhex(r.recvline()[:-2].decode())
r.sendlineafter(b'> ', b'2')
r.sendlineafter(b'gimme your tag: ', tag.hex().encode())
print(r.recvline().strip().decode())