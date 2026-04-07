#!/usr/bin/env python3
import random, math

def prime_factors(n):
    p = 2
    primes = []
    while p * p <= n:
        while n % p == 0:
            primes.append(p)
            n //= p
        p += 1

    if n > 1:
        primes.append(n)

    return primes

def crazy_xor(x):
    primes = prime_factors(x)
    res = 0

    for p1 in primes:
        for p2 in primes:
            if p1 <= p2:
                res ^= math.lcm(p1, p2)
    return res

SECURITY = 7
seeds = []
primes_set = set()
MIN = 100 * 1000
MAX = 500 * 1000

enc = [209, 158, 3, 65, 15, 65, 166, 161, 78, 97, 161, 131, 202, 142, 21, 108, 94, 13, 89, 76, 239, 236, 234, 224, 240, 11, 171, 39, 139, 102, 189, 190, 163, 47, 221, 235, 131, 156, 44, 76, 228, 148, 179, 183, 134, 246, 60, 98, 79, 82, 53, 45, 79, 136]

for x in range(MIN, MAX+1):
    flag = []
    poss = crazy_xor(x)
    poss *= poss
    random.seed(poss)
    for i in range(len(enc)):
        flag.append(enc[i] ^ random.randint(0, 255))

    flag = ''.join(list(map(chr, flag)))
    
    if flag.startswith('ptm'):
        print(flag)
        break
