# Sage
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Util.number import *
from Crypto.Cipher import AES
import hashlib

res = [151991736758354 ,115130361237591,  58905390613532 ,130965235357066 , 74614897867998  ,48099459442369 , 45894485782943   ,7933340009592   ,  25794185638]
ma =[[-10150241248 ,-11679953514  ,-8802490385, -12260198788 ,-10290571893   ,-334269043 ,-11669932300 , -2158827458  ,   -7021995],
[ 52255960212,  48054224859  ,28230779201  ,43264260760  ,20836572799   ,8191198018  ,14000400181  , 4370731005    , 14251110],
[  2274129180  ,-1678741826  ,-1009050115  , 1858488045   , 978763435   ,4717368685   ,-561197285 , -1999440633     ,-6540190],
[ 45454841384  ,34351838833  ,19058600591 , 39744104894  ,21481706222 , 14785555279  ,13193105539  , 2306952916     , 7501297],
[-16804706629 ,-13041485360  ,-8292982763 ,-16801260566  ,-9211427035  ,-4808377155  ,-6530124040  ,-2572433293    , -8393737],
[ 28223439540  ,19293284310   ,5217202426  ,27179839904  ,23182044384  ,10788207024  ,18495479452   ,4007452688   ,  13046387],
[   968256091 , -1507028552  , 1677187853   ,8685590653   ,9696793863   ,2942265602  ,10534454095   ,2668834317   ,   8694828],
[ 33556338459  ,26577210571 , 16558795385  ,28327066095  ,10684900266   ,9113388576  , 2446282316   ,-173705548  ,    -577070],
[ 35404775180  ,32321129676,  15071970630  ,24947264815 , 14402999486   ,5857384379 , 10620159241   ,2408185012 ,     7841686],
]

W = matrix(ZZ, ma)
cc = vector(ZZ, res)

# Babai's Nearest Plane algorithm
def Babai_closest_vector(M, G, target):
    small = target
    for _ in range(5):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -=  M[i] * c
    return target - small

lattice = IntegerLattice(W, lll_reduce=True)
print("LLL done")
gram = lattice.reduced_basis.gram_schmidt()
gram=gram[0]
target = cc
re = Babai_closest_vector(lattice.reduced_basis, gram, target)
print("Closest Vector: {}".format(re))
e = re - cc  # error vector
print("error sum ",e.norm()^2)
# e全为-3,3之间说明正确恢复
print(e)

# R = ZZ
M = Matrix(ZZ, ma)
# ingredients全为素数说明恢复完全正确
ingredients = list(M.solve_left(re))
print("Ingredients: {}".format(ingredients))

key = hashlib.sha256(str(ingredients).encode()).digest()
enc_flag =long_to_bytes(0x1070260d8986d5e3c4b7e672a6f1ef2c185c7fff682f99cc4a8e49cfce168aa0)
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(enc_flag)
print(flag)
# flag{be5152d04a49234a251956a32b}'