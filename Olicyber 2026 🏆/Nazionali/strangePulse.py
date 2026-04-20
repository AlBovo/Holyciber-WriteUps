#!/usr/bin/env python3
import pyshark
import numpy as np

# roba non mia vvv
A = 1337
B = 0xFFFF
C = 100
D = 150
E = 200
F = 250

def v1(s, i):
    a = (s ^ (i * A)) & B
    b = [C, D, E, F]
    np.random.seed(a)
    np.random.shuffle(b)
    return b
# palle ^^^

cap = pyshark.FileCapture('capture.pcap', display_filter='icmp')
ds = []

for i in cap:
    ds.append(list(i.frame_info._all_fields.values())[6])

for s in range(2**16):
    flag = []
    c = 1
    caps, c2 = [], []

    for p in ds:
        if len(flag) == 4:
            if b''.join(flag) == b'flag':
                print("si", s, flag)
            else:
                break
        '''
        0b11111111 >> 6 = 0b11
        0b11111111 >> 4 = 0b1111
        0b11111111 >> 2 = 0b111111
        0b11111111 >> 0 = 0b11111111 & 3 = 0x111
        '''

        if c > 1:
            c2.append(float(p))

        if c % 10 == 0:
            caps.append(c2.copy())
            c2 = []
        
        if c % 40 == 0:
            lvls = v1(s, len(flag))
            t = 0
            for tv,i in enumerate(caps):
                r = float(np.mean(i)) * 1000.0
                if 75.0 <= r < 125.0:
                    bits = lvls.index(100)
                elif 125.0 <= r < 175.0:
                    bits = lvls.index(150)
                elif 175.0 <= r < 225.0:
                    bits = lvls.index(200)
                else:
                    bits = lvls.index(250)
                t |= bits << (6 - 2 * tv)
            flag.append(bytes([t]))
            caps = []

        c += 1
    flag = b''.join(flag)
    if flag.startswith(b'flag{') and flag.endswith(b'}'):
        print(flag, flush=True)
