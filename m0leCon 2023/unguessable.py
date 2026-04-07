#!/usr/bin/env python3
import requests

URL = "http://unguessable.challs.olicyber.it"

## Look in the javascript code for the endpoint
ENDPOINT = "/vjfYkHzyZGJ4A7cPNutFeM/flag"

r = requests.get(URL + ENDPOINT)
print(r.text.strip(), end="")
