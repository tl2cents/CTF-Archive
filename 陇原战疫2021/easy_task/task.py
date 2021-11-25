import random
import hashlib
from Crypto.Util.number import *
from Crypto.Cipher import AES
from secret import flag,V
def get_random_U(n):
    def get_U1():
        A = Matrix(ZZ, n, n)
        for i in range(0,n):
            for j in range(0,n):
                if i<j:
                    A[i,j] = random.randint(1,1000)
                if i==j:
                    A[i,j] = 1
        return A
    def get_U2():
        A = Matrix(ZZ, n, n)
        for i in range(0,n):
            for j in range(0,n):
                if i>j:
                    A[i,j] = random.randint(1,1000)
                if i==j:
                    A[i,j] = 1
        return A
    return get_U1()*get_U2()
def get_public_key():
    U = get_random_U(9)
    V = matrix(V)
    W = V*U
    return W
def get_random_r():
    n = 9
    delta = 4
    r = random_vector(ZZ, n, x=-delta+1, y=delta)
    r = matrix(r)
    return r

def encrypt():
    M = [getPrime(10)for i in range(9)]
    m = matrix(M)
    W = get_public_key()
    r = get_random_r()
    e = m*W+r
    print("e =",e)
    print("W =",W)
    return M
def new_encrypt():
    M = encrypt()
    key = hashlib.sha256(str(M).encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    c = cipher.encrypt(flag).hex()
    print("c =",c)
new_encrypt()
#e = [151991736758354 115130361237591  58905390613532 130965235357066  74614897867998  48099459442369  45894485782943   7933340009592     25794185638]
#W = [-10150241248 -11679953514  -8802490385 -12260198788 -10290571893   -334269043 -11669932300  -2158827458     -7021995]
#[ 52255960212  48054224859  28230779201  43264260760  20836572799   8191198018  14000400181   4370731005     14251110]
#[  2274129180  -1678741826  -1009050115   1858488045    978763435   4717368685   -561197285  -1999440633     -6540190]
#[ 45454841384  34351838833  19058600591  39744104894  21481706222  14785555279  13193105539   2306952916      7501297]
#[-16804706629 -13041485360  -8292982763 -16801260566  -9211427035  -4808377155  -6530124040  -2572433293     -8393737]
#[ 28223439540  19293284310   5217202426  27179839904  23182044384  10788207024  18495479452   4007452688     13046387]
#[   968256091  -1507028552   1677187853   8685590653   9696793863   2942265602  10534454095   2668834317      8694828]
#[ 33556338459  26577210571  16558795385  28327066095  10684900266   9113388576   2446282316   -173705548      -577070]
#[ 35404775180  32321129676  15071970630  24947264815  14402999486   5857384379  10620159241   2408185012      7841686]
#c =1070260d8986d5e3c4b7e672a6f1ef2c185c7fff682f99cc4a8e49cfce168aa0
