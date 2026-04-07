#!/usr/bin/env python3
from z3 import *
import requests

URL = "http://andcipher.challs.olicyber.it/"
flag = [-1 for _ in range(26)]
for _ in range(250):
    json = requests.get(URL + "api/encrypt").json()
    json = bytes.fromhex(json['encrypted'])
    for i in range(26):
        flag[i] = max(flag[i], json[i])
    print("Done round", _) # Just to see the progress
print("".join([chr(i) for i in flag])) # ptm{4nd_c1ph3r_1s_4w3s0m3}
