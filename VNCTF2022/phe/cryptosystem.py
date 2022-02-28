from Crypto.Util.number import*
import random

class CryptoSystem:
    def __init__(self,kbit) :
        self.k_bit = kbit
        self.p_bit = self.k_bit//2
        self.q_bit = self.k_bit - self.p_bit
        self.gen_alice_key()

    def gen_alice_key(self):
        while 1:
            p = getPrime(self.p_bit)
            p_tmp = (p-1)//2
            if isPrime(p_tmp):
                break

        while 1:
            q = getPrime(self.q_bit)
            q_tmp = (q-1)//2
            if isPrime(q_tmp):
                break

        N = p * q 

        while 1:
            g = random.randrange(N*N)
            if  (pow(g,p_tmp * q_tmp,N*N) - 1) %  N == 0 and \
                (pow(g,p_tmp * q_tmp,N*N) - 1) // N >= 1 and \
                (pow(g,p_tmp * q_tmp,N*N) - 1) // N <= N - 1:
                break

        self.alice_pub = (N,g)
        self.alice_sec = (p,q)

    def gen_other_key(self):
        N,g = self.alice_pub
        a = random.randrange(N*N)
        h = pow(g,a,N*N)
        pub = h
        sec = a 
        return pub,sec

    def other_encrypt(self,pk,m):
        N,g = self.alice_pub
        r = random.randrange(N*N)
        A = pow(g,r,N*N)
        B = (pow(pk,r,N*N) * (1 + m * N)) % (N * N)
        return A,B

    def Add(self,dataCipher1,dataCipher2):
        N , g = self.alice_pub
        A1,B1 = dataCipher1
        A2,B2 = dataCipher2

        B = (B1*B2) % (N*N)

        return (A1,A2,B)
 
