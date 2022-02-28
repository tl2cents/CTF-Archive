from Crypto.Util.number import *
from secret import flag,getMyPrime
import hashlib
import random

class SpecialCurve:
    def __init__(self,p,a,b):
        self.p=p
        self.a=a
        self.b=b

    def __str__(self):
        return f'SpecialCurve({self.p},{self.a},{self.b})'

    def add(self,P1,P2):
        x1,y1=P1
        x2,y2=P2
        if x1==0:
            return P2
        elif x2==0:
            return P1
        elif x1==x2 and (y1+y2)%self.p==0:
            return (0,0)
        if P1==P2:
            t=(2*self.a*x1-self.b)*inverse(2*y1,self.p)%self.p
        else:
            t=(y2-y1)*inverse(x2-x1,self.p)%self.p
        x3=self.b*inverse(self.a-t**2,self.p)%self.p
        y3=x3*t%self.p
        return (x3,y3)

    def mul(self,P,k):
        assert k>=0
        Q=(0,0)
        while k>0:
            if k%2:
                k-=1
                Q=self.add(P,Q)
            else:
                k//=2
                P=self.add(P,P)
        return Q

def problem(size,k):
    p=getMyPrime(size)
    x=random.randint(1,p-1)
    y=random.randint(1,p-1)
    e=random.randint(1,p-1)
    a=k*random.randint(1,p-1)**2%p
    b=(a*x**2-y**2)*inverse(x,p)%p
    curve=SpecialCurve(p,a,b)
    G=(x,y)
    Q=curve.mul(G,e)
    print(f'curve={curve}')
    print(f'G={G}')
    print(f'Q={Q}')
    return e

e1=problem(128,1)
e2=problem(256,0)
e3=problem(512,-1)
enc=bytes_to_long(hashlib.sha512(b'%d-%d-%d'%(e1,e2,e3)).digest())^bytes_to_long(flag.encode())
print(f'enc={enc}')
'''
curve=SpecialCurve(233083587295210134948821000868826832947,73126617271517175643081276880688551524,88798574825442191055315385745016140538)
G=(183831340067417420551177442269962013567, 99817328357051895244693615825466756115)
Q=(166671516040968894138381957537903638362, 111895361471674668502480740000666908829)
curve=SpecialCurve(191068609532021291665270648892101370598912795286064024735411416824693692132923,0,58972296113624136043935650439499285317465012097982529049067402580914449774185)
G=(91006613905368145804676933482275735904909223655198185414549961004950981863863, 96989919722797171541882834089135074413922451043302800296198062675754293402989)
Q=(13504049588679281286169164714588439287464466303764421302084687307396426249546, 110661224324697604640962229701359894201176516005657224773855350780007949687952)
curve=SpecialCurve(52373730653143623993722188411805072409768054271090317191163373082830382186155222057388907031638565243831629283127812681929449631957644692314271061305360051,28655236915186704327844312279364325861102737672471191366040478446302230316126579253163690638394777612892597409996413924040027276002261574013341150279408716,42416029226399083779760024372262489355327595236815424404537477696856946194575702884812426801334149232783155054432357826688204061261064100317825443760789993)
G=(15928930551986151950313548861530582114536854007449249930339281771205424453985946290830967245733880747219865184207937142979512907006835750179101295088805979, 29726385672383966862722624018664799344530038744596171136235079529609085682764414035677068447708040589338778102975312549905710028842378574272316925268724240)
Q=(38121552296651560305666865284721153617113944344833289618523344614838728589487183141203437711082603199613749216407692351802119887009907921660398772094998382, 26933444836972639216676645467487306576059428042654421228626400416790420281717654664520663525738892984862698457685902674487454159311739553538883303065780163)
enc=4161358072766336252252471282975567407131586510079023869994510082082055094259455767245295677764252219353961906640516887754903722158044643700643524839069337
'''