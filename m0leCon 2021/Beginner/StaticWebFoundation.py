import requests # analizzando con nmap, dirsearch non si ottiene niente, provo con head e options
site = "http://staticwebfoundation.challs.olicyber.it"
r = requests.options(site)
#print(r.headers) # niente
r = requests.head(site)
#print(r.headers) # strano link
r = requests.get(site + "/o1SfuSXpptIk1p8U0qISobkrYwXSILflr6ZxTsmF?p=banana")
print(r.text, end="")