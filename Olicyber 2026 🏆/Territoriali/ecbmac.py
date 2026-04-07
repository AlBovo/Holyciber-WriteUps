from pwn import *

r = remote("ecb-mac.challs.olicyber.it", 38082)

target_msg = "Questo è un messaggio a caso lungo esattamente 16 blocchi. 16 blocchi sono 16x16 = 256 bytes cioè 2048 bits. Non è facile arrivare ad una lunghezza del genere, dopo un po' finiscono le idee su cosa scrivere. Comunque dovremmo aver quasi finito, ciao!!!!"
target_msg = target_msg.encode()

def rotate_left(block, i):
    return block[i:] + block[:i]

def rotate_right(block, i):
    return block[-i:] + block[:-i]

blocks = [target_msg[i:i+16] for i in range(0, len(target_msg), 16)]

blocks = rotate_right(blocks, 1)

for i in range(0, 16):
    blocks[i] = rotate_right(blocks[i], 1)

assert len(b''.join(blocks)) == 256

r.sendlineafter(b': ', b''.join(blocks).hex())
r.recvuntil(b': ')
s = bytes.fromhex(r.recvline().strip().decode())

s = rotate_right(s, 1)
r.sendlineafter(b': ', s.hex())
r.interactive()