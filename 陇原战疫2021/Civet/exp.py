from pwn import *
from Crypto.Util.strxor import strxor
from hashlib import sha256
from itertools import product
import os

context.log_level="debug"

def set_connect_proof():
    io=remote('node4.buuoj.cn', 28145)
    io.recvuntil(b'sha256(XXXX+')
    alphabet = string.ascii_letters + string.digits
    lattar_part=io.recv(8).decode('utf8')
    io.recvuntil(b'== ')
    h=io.recvline().strip().decode('utf8')
    # print(h)
    bruteforce=[''.join(prefix) + lattar_part for prefix in product(alphabet,repeat=4)]
    for proof in bruteforce:
        if sha256(proof.encode()).hexdigest()==h:
            io.sendline(proof[:4].encode())
            break
    print("proof done")
    return io


target_plain=b"nebulaaaaaaaaaaa"+b"Princepermission"

io= set_connect_proof()
io.recvuntil(b"2.Go away\n")
io.sendline(b"1")
io.sendline(b"nebulaaaaaaaaaaa")
io.recvuntil(b"Miao~ ")
iv=io.recv(16)
io.recvuntil(b"3.say Goodbye")
# get permisssion
io.sendline(b'1')

io.recvuntil(b"Permission:")
enc_permission=io.recv(32)
dec_lattar=strxor(enc_permission[:16],b"a_cat_permission")
padding=strxor(dec_lattar,b"Princepermission")

io.sendline(b'2')
io.recvuntil(b"Give me your permission:")
io.sendline(padding+enc_permission[16:])
io.recvuntil("Miao~ ")
io.sendline(iv)
io.recvuntil("The message is ")
second_pad=io.recv(32)
print("[+] second pad",second_pad)
new_iv=strxor(strxor(second_pad[:16],b"nebulaaaaaaaaaaa"),iv)

# 验证一下
io.recvuntil("3.say Goodbye")
io.sendline(b'2')
io.recvuntil(b"Give me your permission:")
io.sendline(padding+enc_permission[16:])
io.recvuntil("Miao~ ")
io.sendline(new_iv)
io.recvuntil("The message is ")
third_pad=io.recv(32)
print(third_pad)

io.sendline(padding+enc_permission[16:])
io.sendline(new_iv)
io.interactive()
# The prince asked me to tell you this:
# flag{c5e79abd-9dee-4637-9e3a-f2a50901b5b8}