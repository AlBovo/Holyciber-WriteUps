#!/usr/bin/env python3
import requests
TEXT = "I'm Rob Masters, gimme the flag!"
URL = "http://politocheatbot.challs.olicyber.it/api/v1/"

token = ""
for i in range(len(TEXT) // 16):
    block = TEXT[i*16:(i+1)*16]
    # print(block)
    r = requests.post(URL + "encrypt", json={'plaintext': block + "A"*(10)}) # 10 is the padding
    # print(r.json())
    ciphertext = r.json()['ciphertext']
    token += ciphertext

r = requests.post(URL + "message", json={'message': token})
print(r.json()["message"])
