flag = open("output.txt").read()

c = 0
flagc = b''
last = ''
for i in range(len(flag)):
    if last != flag[i]:
        flagc += bytes([c])
        c = 1
        last = flag[i]
    else:
        c += 1

print(flagc)