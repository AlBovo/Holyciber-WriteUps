#!/usr/bin/env python3
from math import gcd
from z3 import *

flag = bytes.fromhex('94c2cbdae5e19ea9d8c697a9aa69a4dfe8dbd9a7686767648fbed1d8daebe5e5eae7ac6c93c49864a4aaa5dbccc7d0d6a6ada897d4e4a48fd3e8a768')
l = len(flag)

ks = []
for k in range(2, l):
    if gcd(k, l) == 1:
        ks.append(k)

print(ks)

for k in ks:
    enc = []
    s = Solver()
    arr = [Int(f'x_{i}') for i in range(l)]

    for i in arr:
        s.add(i > 0, i < 256)
    
    for i in [(k*i-1)%l for i in range(l)]:
        enc.append((arr[i] + arr[(i+k)%l]) % 256)
    
    for i in range(l):
        s.add(enc[i] == flag[i])
    
    while s.check() == sat:
        m = s.model()
        dec = []
        for i in arr:
            dec.append(m[i].as_long())
            s.add(i != m[i].as_long())
        print(b''.join(bytes([i]) for i in dec))

# for k in ks:
#     enc = []
#     mat = [(k*i-1) % l for i in range(l)]

#     # for i in [(k*i-1)%l for i in range(l)]:
#     #     enc.append((flag[i] + flag[(i+k)%l]) % 256)
    
#     for i, c in enumerate(flag):

    

#     r = b''.join(bytes([i]) for i in enc)
#     print(r)