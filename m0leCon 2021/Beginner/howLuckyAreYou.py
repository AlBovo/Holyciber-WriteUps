from pwn import *
x = 1804289383 # viene sempre generato uguale
r = remote("lucky.challs.olicyber.it", 11101)
r.recv()
r.sendline(str(x).encode())
r.recvuntil(b"ptm")
print("ptm" + r.recv().decode())
