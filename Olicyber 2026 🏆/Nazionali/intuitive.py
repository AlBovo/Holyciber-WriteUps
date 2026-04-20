#!/usr/bin/env python3
from pwn import *
from Crypto.Util.Padding import pad
import json

r = remote("intuitive.challs.nazionale.olicyber.it", 38097)

payload = {"method":"query", "m": (b'a' * 16).hex()}

r.sendlineafter(b'> ', json.dumps(payload).encode())

tag = bytes.fromhex(json.loads(r.recvline().decode())["tag"])
assert len(tag) == 16 * 2
iv = tag[:16]
tag = tag[-16:]

pl = xor(b'a'*16, iv)
assert len(pl) == 16

payload = {"method":"solve", "m": pl.hex(), "tag": "0" * (16 * 2) + tag.hex()}

r.sendlineafter(b'> ', json.dumps(payload).encode())

r.interactive()