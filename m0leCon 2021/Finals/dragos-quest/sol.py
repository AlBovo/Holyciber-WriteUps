#!/usr/bin/env python3
from pwn import *
import random, subprocess

def simulate_games(seed, N):
    moves = ["R", "P", "S", "L", "V"]
    random.seed(seed)
    return "".join(moves[random.randint(0,4)] for _ in range(N))

r = remote("dragos-quest.challs.olicyber.it", 18002)
r.sendlineafter(b'> ', b'2')
for i in range(100):
    a, b, c = r.recvline().strip().decode().split(' ')
    a, b, c = int(a), int(b), int(c)
    s = simulate_games(a, b)
    p = subprocess.run(
        "./solver", 
        stdout=subprocess.PIPE,
        input=" ".join([s, str(b), str(c)]).encode(),
        check=True
    )
    sout = p.stdout.decode().strip()
    r.sendlineafter(b': ', sout.encode())
    r.recvline()

print(r.recvline().strip().decode())