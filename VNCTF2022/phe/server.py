from Crypto.Util.number import*
from cryptosystem import CryptoSystem 
from secret import flag
import random
from hashlib import sha256
import socketserver
import signal
import string 
table = string.ascii_letters+string.digits
MENU = b'What do you want to get?\n[1]the pk list\n[2]Alice Public Parameters\n[3]Mixed Flag\n[4]exit'
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

    def recv(self, prompt=b'SERVER <INPUT>: '):
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

    def gen_participation_key_pair(self):
        participation_pk_list = []
        participation_sk_list = []

        for i in range(6):
            part_pk,part_sk = self.alice_cryptosystem.gen_other_key()
            participation_pk_list.append(part_pk)
            participation_sk_list.append(part_sk)
        return part_pk

    def handle(self):
        self.alice_cryptosystem = CryptoSystem(1024)
        participation_pk_list = self.gen_participation_key_pair()
        proof = self.proof_of_work()
        if not proof:
            self.request.close()
        signal.alarm(60)
        flag_list   = [bytes_to_long(flag[i*5:i*5+5]) for i in range(6)]
        cipher_list = [self.alice_cryptosystem.other_encrypt(participation_pk_list[i],flag_list[i]) for i in range(6)]
        mixed_data  = [self.alice_cryptosystem.Add(cipher_list[i],cipher_list[i+1]) for i in range(5)]

        while 1:
            self.send(MENU)
            option = self.recv()
            if option == b'1':
                self.send(b"[~]My pk_list is:")
                self.send(str(participation_pk_list).encode())

            elif option == b'2':
                self.send(b"[~]Alice public_parameters is")
                self.send(str(self.alice_cryptosystem.alice_pub).encode())

            elif option == b'3':
                self.send(b'[~]What you want is the flag!')
                self.send(str(mixed_data).encode())

            else:
                break
        self.request.close()

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10005
    print("HOST:POST " + HOST+":" + str(PORT))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()