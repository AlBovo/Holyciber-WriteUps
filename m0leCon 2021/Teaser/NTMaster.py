from pwn import *
'''
Codice usato in sagemath per risolvere l'equazione dove 227 è N
a, b = var('a b')
solve([gcd(a,b)+lcm(a,b)==227], [a,b]) # -a*b + n - 1 == 0
'''
conn = remote("nt-master.challs.olicyber.it", 11001)
for i in range(10):
    conn.recvuntil(b"N = ")
    f = conn.recvline().decode().replace("\n","")
    s = int(f, 10)
    print(s)
    conn.sendline(f"{s-1} 1".encode())
    
print(conn.recv(1000).decode())