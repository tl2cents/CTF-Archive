from Crypto.Cipher import AES
import os
from hashlib import sha256
import socketserver
import signal
import string
import random

table = string.ascii_letters + string.digits
BANNER = br'''
 .d8888b.  d8b                   888                            888             
d88P  Y88b Y8P                   888                            888             
888    888                       888                            888             
888        888 888  888  .d88b.  888888        .d8888b  8888b.  888888          
888        888 888  888 d8P  Y8b 888          d88P"        "88b 888             
888    888 888 Y88  88P 88888888 888          888      .d888888 888             
Y88b  d88P 888  Y8bd8P  Y8b.     Y88b.        Y88b.    888  888 Y88b.           
 "Y8888P"  888   Y88P    "Y8888   "Y888        "Y8888P "Y888888  "Y888          
                                                                                
                                                                                
                                                                                
 .d888                        8888888b.          d8b                            
d88P"                         888   Y88b         Y8P                            
888                           888    888                                        
888888  .d88b.  888d888       888   d88P 888d888 888 88888b.   .d8888b  .d88b.  
888    d88""88b 888P"         8888888P"  888P"   888 888 "88b d88P"    d8P  Y8b 
888    888  888 888           888        888     888 888  888 888      88888888 
888    Y88..88P 888           888        888     888 888  888 Y88b.    Y8b.     
888     "Y88P"  888           888        888     888 888  888  "Y8888P  "Y8888
'''

guard_menu = br'''
1.Tell the guard my name
2.Go away
'''

cat_menu = br'''1.getpermission
2.getmessage
3.say Goodbye
'''


def Pad(msg):
    return msg + os.urandom((16 - len(msg) % 16) % 16)


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

    def recv(self, prompt=b'[-] '):
        self.send(prompt, newline=False)
        return self._recvall()

    def proof_of_work(self):
        proof = (''.join([random.choice(table) for _ in range(12)])).encode()
        sha = sha256(proof).hexdigest().encode()
        self.send(b"[+] sha256(XXXX+" + proof[4:] + b") == " + sha)
        XXXX = self.recv(prompt=b'[+] Give Me XXXX :')
        if len(XXXX) != 4 or sha256(XXXX + proof[4:]).hexdigest().encode() != sha:
            return False
        return True

    def register(self):
        self.send(b'')
        username = self.recv()
        return username

    def getpermission(self, name, iv, key):
        aes = AES.new(key, AES.MODE_CBC, iv)
        plain = Pad(name)+b"a_cat_permission"
        return aes.encrypt(plain)

    def getmessage(self, iv, key, permission):
        aes = AES.new(key, AES.MODE_CBC, iv)
        return aes.decrypt(permission)

    def handle(self):
        signal.alarm(50)
        if not self.proof_of_work():
            return
        self.send(BANNER, newline=False)
        self.key = os.urandom(16)
        self.iv = os.urandom(16)
        self.send(b"I'm the guard, responsible for protecting the prince's safety.")
        self.send(b"You shall not pass, unless you have the permission of the prince.")
        self.send(b"You have two choices now. Tell me who you are or leave now!")
        self.send(guard_menu, newline=False)
        option = self.recv()
        if option == b'1':
            try:
                self.name = self.register()
                self.send(b"Hello " + self.name)
                self.send(b"Nice to meet you. But I can't let you pass. I can give you a cat. She will play with you")
                self.send(b'Miao~ ' + self.iv)
                for i in range(3):
                    self.send(b"I'm a magic cat. What can I help you")
                    self.send(cat_menu, newline=False)
                    op = self.recv()
                    if op == b'1':
                        self.send(b"Looks like you want permission. Here you are~")
                        permission = self.getpermission(self.name, self.iv, self.key)
                        self.send(b"Permission:" + permission)
                    elif op == b'2':
                        self.send(b"Looks like you want to know something. Give me your permission:")
                        permission = self.recv()
                        self.send(b"Miao~ ")
                        iv = self.recv()
                        plain = self.getmessage(iv, self.key, permission)
                        self.send(b"The message is " + plain)
                    elif op == b'3':
                        self.send(b"I'm leaving. Bye~")
                        break
                self.send(b"Oh, you're here again. Let me check your permission.")
                self.send(b"Give me your permission:")
                cipher = self.recv()
                self.send(b"What's the cat tell you?")
                iv = self.recv()
                plain = self.getmessage(iv, self.key, cipher)
                prs, uid = plain[16:],plain[:16]
                if prs != b'Princepermission' or uid != self.name:
                    self.send(b"You don't have the Prince Permission. Go away!")
                    return
                else:
                    self.send(b"Unbelievable! How did you get it!")
                    self.send(b"The prince asked me to tell you this:")
                    f = open('flag.txt', 'rb')
                    flag = f.read()
                    f.close()
                    self.send(flag)
            except:
                self.request.close()
        if option == b'2':
            self.send(b"Stay away from here!")
        self.request.close()


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10005
    print("HOST:POST " + HOST + ":" + str(PORT))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()
