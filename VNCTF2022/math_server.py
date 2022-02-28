from Crypto.Util.number import*
import random
from secret import flag,check
from hashlib import sha256
import socketserver
import signal
import string 

table = string.ascii_letters+string.digits
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
        proof = (''.join([random.choice(table)for _ in range(20)])).encode()
        sha = sha256(proof).hexdigest().encode()
        self.send(b"[+] sha256(XXXX+" + proof[4:] + b") == " + sha )
        XXXX = self.recv(prompt = b'[+] Plz Tell Me XXXX :')
        if len(XXXX) != 4 or sha256(XXXX + proof[4:]).hexdigest().encode() != sha:
            return False
        return True

    def handle(self):
        proof = self.proof_of_work()
        if not proof:
            self.request.close()
        counts = 0
        signal.alarm(60)
        for i in range(777):
            times = getPrime(32)
            self.send(b'plz give me the ' + str(times).encode() + b'th (n) that satisfying (2^n-1) % 15 == 0:')
            n = int(self.recv())
            a , ret = check(times,n)
            if a == True:
                self.send(ret.encode())
                counts += 1
            else:
                self.send(ret.encode())
        if counts == 777:
            self.send(b'You get flag!')
            self.send(flag)
        else:
            self.send(b'something wrong?')
        self.request.close()

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10001
    print("HOST:POST " + HOST+":" + str(PORT))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever() 
