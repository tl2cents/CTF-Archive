from Crypto.Util.number import bytes_to_long,inverse,getPrime
from Crypto.Cipher import AES
from Crypto.Util import Counter
from hashlib import sha256
from secret import flag
import socketserver
import signal
import string
import random
import json
import time
import os

table = string.ascii_letters+string.digits

class MAC:
    def __init__(self,n = None,k = None):
        if n == None:
            p,q = getPrime(1024),getPrime(1024)
            n = p*q
        if k == None:
            k = random.randrange(1,n)
        self.key = (k , n)

    def sign(self,msg ,r):
        k , n = self.key
        S1 = inverse(2,n) * (msg * inverse(r,n) + r) % n
        S2 = k * inverse(2,n) * (msg * inverse(r,n) - r) % n
        return (S1 , S2)

class my_AES_MAC:
    def __init__(self,key:bytes,authdate:int,iv:bytes,n:int,k:int):
        self.MAC = MAC(n,k)
        self.iv = iv
        self.key = key
        self.ctr = Counter.new(128, initial_value=bytes_to_long(self.iv))

        self.authdate = authdate

    def encrypt(self,msg):
        assert len(msg) % 16 == 0
        ctr_aes = AES.new(key = self.key , mode = AES.MODE_CTR , counter = self.ctr)
        cipher = ctr_aes.encrypt(msg)
        tag = self._mac(msg)
        return cipher , tag
    
    def decrypt(self,cipher):
        assert len(cipher) % 16 == 0
        ctr_aes = AES.new(key = self.key , mode = AES.MODE_CTR , counter = self.ctr)
        msg = ctr_aes.decrypt(cipher)
        tag = self._mac(msg)
        return msg , tag

    def _mac(self,msg):
        auth_date = self.authdate
        msg_state = [bytes_to_long(msg[i*16:(i+1)*16]) for i in range(len(msg)//16)]
        auth_date = bytes_to_long(sha256(str(self.MAC.sign(auth_date,auth_date)).encode()).digest()[:16])
        for plain_state in msg_state:
            auth_date ^= plain_state
            auth_date = bytes_to_long(sha256(str(self.MAC.sign(auth_date,auth_date)).encode()).digest()[:16])
        return hex(auth_date)[2:]

def pad(msg):
    tmp = 16 - len(msg)%16
    return msg + bytes([tmp] * tmp )

def get_token(id:str,nonce:bytes,_time:int):
    msg = {"id":id,"admin":0,"nonce":nonce.hex(),"time":_time}
    msg = str(json.dumps(msg)).encode()
    return msg

MENU = br'''
[R]egister.
[L]ogin.
[T]ime.
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
        proof = (''.join([random.choice(table)for _ in range(20)])).encode()
        sha = sha256(proof).hexdigest().encode()
        self.send(b"[+] sha256(XXXX+" + proof[4:] + b") == " + sha )
        XXXX = self.recv(prompt = b'[+] Plz Tell Me XXXX :')
        if len(XXXX) != 4 or sha256(XXXX + proof[4:]).hexdigest().encode() != sha:
            return False
        return True

    def register(self):
        self.send(b'Now,you can register!')
        username = self.recv(b"input your username:").decode()
        if username in self.UsernameDict:
            self.send(b'Sorry,you\'re already registered...')
            return 
        elif len(username) >= 20:
            self.send(b'Sorry,your username can\'t be longer than 20...')
            return
        nonce = os.urandom(8)
        
        token = get_token(username,nonce,int(time.time()))
        print(token)
        cipher_token,tag = self.myAES_MAC.encrypt(pad(token))
        self.UsernameDict[username] = tag
        self.send(b'Hello!' + username.encode() + b',your encrypted token is:' + cipher_token + b',your nonce is:' + nonce)
        return 

    def login(self):
        self.send(b'Now,you can Login!')
        username = self.recv(b"input your username:").decode()
        if username not in self.UsernameDict:
            self.send(b'Sorry,you should register first...')
            return 
        verify_tag = self.UsernameDict[username]
        cipher_token = self.recv(b"input your encrypt token:")
        try:
            msg,tag = self.myAES_MAC.decrypt(cipher_token)
        except:
            self.send(b"Error.Something Wrong!")
            return 
        if tag != verify_tag :
            self.send(b'What you want to do????You are not admin!!!Get Out!')
            return 

        try:
            token_dict = json.loads(msg.decode('latin-1').strip().encode('utf-8'))
            print(token_dict)
        except:
            self.send(b'Try again.')
            return

        ID = token_dict["id"]
        if ID != username:
            self.send(b'Your ID is Error!')
            return

        elif abs(int(time.time()) - token_dict['time']) >= 1:
            self.send(b'Time Error!')
            return 

        elif token_dict['admin'] != True:
            self.send(b"Login successfully!You're not the admin.")
            return
        
        else:
            self.send(b"Login successfully!You're the admin.I'll give you flag")
            self.send(flag)
            return True

    def time(self):
        the_time = int(time.time())
        self.send(b'[CLOCK]:Time is '+str(the_time).encode())
        return

    def handle(self):
        proof = self.proof_of_work()
        if not proof:
            self.request.close()

        key = os.urandom(16)
        iv = os.urandom(16)
        n,k = 29565257570489493164427390877410900545824625703962319855621334079494703727346988967759564737312591274593942666331170929199052211640195975899683621245395042098684333453410290234806497587218180981357077108747031132527872104593857431004938546196291838454363210160523056655241077785807872947160975977494982149279936648265245652626566325894240170664518173775664355485266789675607304229260821656473956261151351981701194581915166360063884959052198400155029734514944995401830772981304787973469971707027845783791381251396124996288068021123539379965431760752823787508947202231972426835944509818558924626408498815691974695983201,24201257704950503060010702692404648152575233795097588316056239197497942816871077020805340141785254065908910410127944106256655668000911477285356279748662037157388065946700206837534962537378301275862661039121538690201521279246564784038236222871040767788330123424216993356614134450330399413325285093482186714556708068544274657400339702587318360110370726928863579989028869376855768346506291925070244678845911191834738006434042750513716108839497707873708939151542911364096577649775300044250255345603901520095794012422597007179308072924435071075461683793927976009848905440238844498764486768376551075245445678428286401406794
        authdate = os.urandom(16)
        self.myAES_MAC = my_AES_MAC(key,bytes_to_long(authdate),iv,n,k)
        self.send(b'my server authdate is:' + authdate)
        self.UsernameDict = {}

        signal.alarm(60)
        while 1:
            self.send(MENU)
            option = self.recv(b'\n==plz give me your option==\n[IN]:')
            if option == b'R':
                self.register()
            elif option == b'L':
                self.login()
                break
            elif option == b'T':
                self.time()
            else:
                break
        self.request.close()

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10007
    print("HOST:POST " + HOST+":" + str(PORT))
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever() 
