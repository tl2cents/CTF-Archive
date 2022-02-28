from Crypto.Util.number import *
from hashlib import *
from secret import secretkey,flag,ezmath_flag
import socketserver
import os
import signal
import string
assert len(bin(secretkey)) == 169

table = string.ascii_letters+string.digits

class PseudoRandomNumbersGenerators:
    def __init__(self,seed1,seed2):
        self.state_a = seed1
        self.state_b = seed2
        self.a = getRandomNBitInteger(160)
        self.b = getRandomNBitInteger(160)
        self.c = getRandomNBitInteger(160)
        self.M = 1 << 512

    def GetNext(self):
        ret = (self.state_a * self.a + self.state_b * self.b + self.c) % self.M
        self.state_a = self.state_b
        self.state_b = ret
        return ret

    def GetSomethingUseful(self,admin):
        if admin == True:
            return self.a,self.b,self.c
        else:
            return "You can't get anything here!Get out!"
    
    def choice(self,input):
        length = len(input)
        tmp = self.GetNext() % length
        return input[tmp]

class DigitalSignatureAlgorithm:
    def __init__(self,RANDOM):
        self.p = 8945295668911819059540208265461979177678201229057426412681001447446107919117765962027889488459965388254641301806100385155760254966914075104367813869235667
        self.q = 4472647834455909529770104132730989588839100614528713206340500723723053959558882981013944744229982694127320650903050192577880127483457037552183906934617833
        self.g = 3
        self.Random = RANDOM

    def verify(self, m, y, sig):
        r, s = sig
        if (not (1 <= r <= self.q - 1)) or (not (1 <= s <= self.q - 1)): 
            return False
        z = bytes_to_long(sha256(m).digest())
        w = inverse(s, self.q)
        u1 = (z * w) % self.q
        u2 = (r * w) % self.q
        v = (pow(self.g, u1, self.p) * pow(y, u2, self.p)) % self.p % self.q
        return r == v

    def sign(self, m , x):
        z = bytes_to_long(sha256(m).digest())
        while 1:
            k = self.Random.GetNext() % self.q 
            r = pow(self.g , k, self.p) % self.q
            s = (inverse(k, self.q) * (z + x * r)) % self.q
            if (s != 0) and (r != 0) :
                return (r, s)

RANDOM = PseudoRandomNumbersGenerators(getPrime(120),getPrime(120))
DSA = DigitalSignatureAlgorithm(RANDOM)
x = secretkey
y = pow(DSA.g,x,DSA.p)

MENU = br'''
[S]ign.
[V]erify(or get flag).
[I]dentify.
[E]xit.
'''

class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline:
                msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b''):
        self.send(prompt, newline=False)
        return self._recvall()

    def proof_of_work(self):
        proof = (''.join([RANDOM.choice(table)for _ in range(20)])).encode()
        sha = sha256(proof).hexdigest().encode()
        self.send(b"[+] sha256(XXXX+" + proof[4:] + b") == " + sha )
        XXXX = self.recv(prompt = b'[+] Plz Tell Me XXXX :')
        if len(XXXX) != 4 or sha256(XXXX + proof[4:]).hexdigest().encode() != sha:
            return False
        return True

    def sign(self):
        m0 = b'dawn'
        m1 = b'whisper'
        m2 = b'want flag'
        sign0 = DSA.sign(m0,x)
        sign1 = DSA.sign(m1,x)
        sign2 = DSA.sign(m2,x)

        self.send(b'sign of (dawn) is: '      + str(sign0).encode())
        self.send(b'sign of (whisper) is: '   + str(sign1).encode())
        self.send(b'sign of (want flag) is: ' + str(sign2).encode())

    def identify(self):
        rec_key = self.recv(b'flag of ezmath is :')
        ret = RANDOM.GetSomethingUseful(rec_key == ezmath_flag)
        self.send(str(ret).encode())

    def verify(self):
        msg = self.recv(b'msg:')
        r = int(self.recv(b'r:'))
        s = int(self.recv(b's:'))
        sig = (r,s)
        if msg == b"I'm Admin.Plz give me flag!":
            if DSA.verify(msg,y,sig):
                self.send(b'Yes Sir!Thank you Sir!')
                return flag
            else:
                self.send(b'Who are U?Get out!')
                return False
        else:
            if DSA.verify(msg,y,sig):
                self.send(b'Yeah!You sign successfully!')
                return os.urandom(32)

    def handle(self):
        proof = self.proof_of_work()
        if not proof:
            self.request.close()
        signal.alarm(60)
        chance = 0
        while 1:
            self.send(MENU)
            option = self.recv(b'\n==plz give me your option==\n[IN]:')
            if option == b'S':
                if chance == 0:
                    self.sign()
                    chance += 1
                else:
                    self.send(b'ERROR! You only have one time!')
            elif option == b'V':
                ret = self.verify()
                if ret :
                    self.send(b'Your Flag is :' + ret)
                break
            elif option == b'I':
                self.identify()
            else:
                break
        self.request.close()

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10004
    print("HOST:POST " + HOST+":" + str(PORT))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever() 
