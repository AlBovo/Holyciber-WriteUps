#!/usr/bin/env python3
from z3 import *
from pwn import xor

def c1(a3):
    return 80 * (a3 + 7) + 6

def c2(a3):
    return 12 * a3 + 15

def c3(a3):
    return 4 * a3 + 15

def c4(a3):
    return 6 * (2 * (a3 + 16) + 8)

def c5(a3):
    return 5400 * (a3 + 5)

def c6(a3):
    return 8 * (a3 + 6) + 25

def c7(a3):
    return 7 * (a3 + 2) + 6

def c8(a3):
    return 6 * (a3 + 10) + 14

def c9(a3):
    return 9 * (9 * (a3 + 6) + 10)

def c10(a3):
    return 8 * (a3 + 9) + 8

def c11(a3):
    return 784 * a3

def c12(a3):
    return 5 * (9 * (a3 + 1) + 3) + 6

def c13(a3):
    return 576 * a3 + 13

def c14(a3):
    return 4 * (252 * a3 + 6)

def c15(a3):
    return 2916 * a3

def c16(a3):
    return 432 * (a3 + 7)

def c17(a3):
    return 50 * (a3 + 4) + 3

def c18(a3):
    return 8 * a3 + 19

def c19(a3):
    return 9 * (50 * a3 + 10) + 9

def c20(a3):
    return 80 * (a3 + 4) + 2

def c21(a3):
    return 6 * (a3 + 10) + 16

def c22(a3):
    return 180 * (a3 + 8)

def c23(a3):
    return 20 * (a3 + 2) + 9

def c24(a3):
    return 10 * (a3 + 20)

def c25(a3):
    return 4 * (6 * (a3 + 5) + 7)

def c26(a3):
    return 180 * (a3 + 5) + 2

def c27(a3):
    return 21 * (9 * a3 + 7) + 9

def c28(a3):
    return 8 * (a3 + 36)

def c29(a3):
    return 2 * a3 + 9

def c30(a3):
    return 5 * (16 * (a3 + 2) + 7)

def c31(a3):
    return 7 * (5 * a3 + 6) + 9

def c32(a3):
    return a3 + 19

inputs = [6326, 2259, 455, 1848, 275400, 745, 1714, 1076, 12645, 2120, 153664, 10371, 37453, 203640, 691092, 36288, 753, 2011, 59949, 18082, 538, 12420, 2529, 1130, 6076, 11702, 47217, 1056, 207, 11315, 2676, 261]
solution = [Int('sol%d' % i) for i in range(len(inputs))]

s = Solver()

for i in range(len(inputs)):
    exec(f's.add(c{i+1}(solution[{i}]) == inputs[{i}])')

print(s.check())

m = s.model()
d = b""
for i in range(len(inputs)):
    d += (m[solution[i]].as_long()).to_bytes(1, 'little')

# codice per ottenere il dex con il decrypt (decompiler.com)
'''
with open("enc_payload", "rb") as payload:
    enc_payload = payload.read()

payload = xor(enc_payload, d)
with open("payload.dex", "wb") as f:
    f.write(payload)
'''
def decrypt(key):
    i = 0
    upperCase = "NUKRPFUFALOXYLJUDYRDJMXHMWQW"
    str2 = ""
    for i2 in range(len(upperCase)):
        str2 += chr((((ord(upperCase[i2]) - ord(key[i])) + 26) % 26) + 65)
        i = (i + 1) % len(key)
    return str2

print("ptm{" + decrypt("EASYPEASY") + "}")
