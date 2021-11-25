from pwn import *
from Crypto.Util.strxor import strxor
from hashlib import sha256
from itertools import product
import os
import string

import hashlib
from z3 import *
from pwn import *
import re
import string
import time
# Hack for mbruteforce on macos
# import multiprocessing
# multiprocessing.set_start_method('fork')


MASK = 0xFFFFFFFFFFFFFFFF
# context.terminal = ["tmux","split","-h"]
context.log_level = 'DEBUG'

start = b''
target_hash = ''

def hhash(end):
    end = end.encode()
    return hashlib.sha256(start+end).hexdigest() == target_hash

def solve_init(states):
    print(states)
    init_s0, init_s1 = BitVecs('init_s0 init_s1', 64)
    s0_ = init_s0
    s1_ = init_s1
    s = Solver()
    for i in states:
        s1 = s0_
        s0 = s1_
        s1 ^= (s1 << 23)
        s1 ^= LShR(s1, 17)
        s1 ^= s0
        s1 ^= LShR(s0, 26)
        s.add(s0+s1 == i)
        s0_ = s0
        s1_ = s1
    print(s.check())
    m = s.model()
    return m[init_s0].as_long(),m[init_s1].as_long()


class XorShift128():
    def __init__(self,s0,s1) -> None:
        self.s0 = s0
        self.s1 = s1
    def get(self):
        s0_ = self.s1
        s1_ = self.s0
        s1_ ^= (s1_ << 23) & MASK
        s1_ ^= (s1_ >> 17) & MASK
        s1_ ^= s0_
        s1_ ^= ( s0_>>26 ) & MASK
        self.s0 = s0_
        self.s1 = s1_
        return (self.s0 + self.s1) & MASK 

context.log_level="debug"

def set_connect_proof():
    # io=remote("121.36.201.164", 9999)
    io=process("./p0o0w/p0o0w")
    io.recvuntil(b'sha256(')
    alphabet = string.ascii_letters + string.digits
    lattar_part=io.recv(13).decode('utf8')
    io.recvuntil(b'== ')
    h=io.recvline().strip().decode('utf8')
    # print(h)
    io.recvuntil(b'tell me the ? in sha256(?):')
    bruteforce=[ lattar_part + ''.join(prefix) for prefix in product(alphabet,repeat=3)]
    for proof in bruteforce:
        if sha256(proof.encode()).hexdigest()==h:
            io.sendline(proof.encode())
            break
    print("proof done")
    return io

def proof(io,i):
    io.recvuntil(b'sha256(')
    alphabet = "abcdef" + string.digits
    lattar_part=io.recv(16-i).decode('utf8')
    print("[+] lattar part",lattar_part)
    io.recvuntil(b'== ')
    h=io.recvline().strip().decode('utf8')
    print("[+] hash",h)
    io.recvuntil(b'tell me the ? in sha256(?):')
    bruteforce=[ lattar_part + ''.join(prefix) for prefix in product(alphabet,repeat=i)]
    for proof in bruteforce:
        if sha256(proof.encode()).hexdigest()==h:
            io.sendline(proof.encode())
            print("proof %d done"%i)
            break
io=set_connect_proof()
proof(io,4)
proof(io,5)
proof(io,6)
proof(io,7)
proof(io,8)
io.interactive()