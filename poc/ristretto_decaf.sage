#!/usr/bin/sage
# vim: syntax=python

import binascii
class InvalidEncodingException(Exception): pass

# Inspired by Mike Hamburg's library. Thanks, Mike
def lobit(x): return int(x) & 1
def negative(x): return lobit(x)
def enc_le(x,n): return bytearray([int(x)>>(8*i) & 0xFF for i in range(n)])
def dec_le(x): return sum(b<<(8*i) for i,b in enumerate(x))
def randombytes(n): return bytearray([randint(0,255) for _ in range(n)])

def xsqrt(x,exn=InvalidEncodingException("Not on curve")):
    """Return sqrt(x)"""
    if not is_square(x): raise exn
    s = sqrt(x)
    if negative(s): s=-s
    return s

def isqrt(x,exn=InvalidEncodingException("Not on curve")):
    """Return 1/sqrt(x)"""
    if x==0: return 0
    if not is_square(x): raise exn
    s = sqrt(x)
    return 1/s

def isqrt_i(x):
    """Return 1/sqrt(x) or 1/sqrt(zeta * x)"""
    if x==0: return True,0
    gen = x.parent(-1)
    while is_square(gen): gen = sqrt(gen)
    if is_square(x): return True,1/sqrt(x)
    else: return False,1/sqrt(x*gen)

class QuotientEdwardsPoint(object):
    """Abstract class for point an a quotiented Edwards curve; needs F,a,d,cofactor to work"""
    def __init__(self,x=0,y=1):
        x = self.x = self.F(x)
        y = self.y = self.F(y)
        if y^2 + self.a*x^2 != 1 + self.d*x^2*y^2:
            raise NotOnCurveException(str(self))

    def __repr__(self):
        return "%s(0x%x,0x%x)" % (self.__class__.__name__, self.x, self.y)

    def __iter__(self):
        yield self.x
        yield self.y

    def __add__(self,other):
        x,y = self
        X,Y = other
        a,d = self.a,self.d
        return self.__class__(
            (x*Y+y*X)/(1+d*x*y*X*Y),
            (y*Y-a*x*X)/(1-d*x*y*X*Y)
        )

    def __neg__(self): return self.__class__(-self.x,self.y)
    def __sub__(self,other): return self + (-other)
    def __rmul__(self,other): return self*other
    def __eq__(self,other):
        """NB: this is the only method that is different from the usual one, as per draft"""
        x,y = self
        X,Y = other
        return x*Y == X*y or (self.cofactor==8 and -self.a*x*X == y*Y)
    def __ne__(self,other): return not (self==other)

    def __mul__(self,exp):
        exp = int(exp)
        if exp < 0: exp,self = -exp,-self
        total = self.__class__()
        work  = self
        while exp != 0:
            if exp & 1: total += work
            work += work
            exp >>= 1
        return total

    def xyzt(self):
        x,y = self
        z = self.F.random_element()
        return x*z,y*z,z,x*y*z

    def torque(self):
        """Apply cofactor group, except keeping the point even"""
        if self.cofactor == 8:
            if self.a == -1: return self.__class__(self.y*self.i, self.x*self.i)
            if self.a ==  1: return self.__class__(-self.y, self.x)
        else:
            return self.__class__(-self.x, -self.y)

    def random_scalar(self):
        return random.randint(1, self.order-1)

    def key_gen(self):
        skS = ZZ(self.random_scalar())
        pkS = self.base() * skS
        return skS, pkS

    # Utility functions
    @classmethod
    def bytesToGf(cls,bytes,mustBeProper=True,mustBePositive=False,maskHiBits=False):
        """Convert little-endian bytes to field element, sanity check length"""
        if len(bytes) != cls.encLen and mustBeProper:
            raise InvalidEncodingException("wrong length %d" % len(bytes))
        s = dec_le(bytes)
        if mustBeProper and s >= cls.F.order():
            raise InvalidEncodingException("%d out of range!" % s)
        bitlen = int(ceil(N(log(cls.F.order(),2.))))
        if maskHiBits: s &= 2^bitlen-1
        s = cls.F(s)
        if mustBePositive and negative(s):
            raise InvalidEncodingException("%d is negative!" % s)
        return s

    @classmethod
    def gfToBytes(cls,x,mustBePositive=False):
        """Convert little-endian bytes to field element, sanity check length"""
        if negative(x) and mustBePositive: x = -x
        return enc_le(x,cls.encLen)

class DecafPoint(QuotientEdwardsPoint):
    """Tweaked for compatibility with Ristretto, as in draft"""
    def encode(self):
        """Unoptimized specification for encoding"""
        a,d = self.a,self.d
        x,y = self
        if x==0 or y==0: return(self.gfToBytes(0))

        if self.cofactor==8 and negative(x*y*self.isoMagic):
            x,y = self.torque()

        sr = xsqrt(1-a*x^2)
        altx = x*y*self.isoMagic / sr
        if negative(altx): s = (1+sr)/x
        else:              s = (1-sr)/x

        return self.gfToBytes(s,mustBePositive=True)

    @classmethod
    def decode(cls,s):
        """Unoptimized specification for decoding"""
        a,d = cls.a,cls.d
        s = cls.bytesToGf(s,mustBePositive=True)

        if s==0: return cls()
        t = xsqrt(s^4 + 2*(a-2*d)*s^2 + 1)
        altx = 2*s*cls.isoMagic/t
        if negative(altx): t = -t
        x = 2*s / (1+a*s^2)
        y = (1-a*s^2) / t

        if cls.cofactor==8 and (negative(x*y*cls.isoMagic) or y==0):
            raise InvalidEncodingException("x*y is invalid: %d, %d" % (x,y))

        return cls(x,y)

class RistrettoPoint(QuotientEdwardsPoint):
    def encodeSpec(self):
        """Unoptimized specification for encoding"""
        x,y = self
        if self.cofactor==8 and (negative(x*y) or y==0): (x,y) = self.torque()
        if y == -1: y = 1 # Avoid divide by 0; doesn't affect impl

        if negative(x): x,y = -x,-y
        s = xsqrt(self.mneg*(1-y)/(1+y),exn=Exception("Unimplemented: point is odd: " + str(self)))
        return self.gfToBytes(s)

    @classmethod
    def decodeSpec(cls,s):
        """Unoptimized specification for decoding"""
        s = cls.bytesToGf(s,mustBePositive=True)

        a,d = cls.a,cls.d
        x = xsqrt(4*s^2 / (a*d*(1+a*s^2)^2 - (1-a*s^2)^2))
        y = (1+a*s^2) / (1-a*s^2)

        if cls.cofactor==8 and (negative(x*y) or y==0):
            raise InvalidEncodingException("x*y has high bit")

        return cls(x,y)

    def encode(self):
        """Encode, optimized version"""
        a,d,mneg = self.a,self.d,self.mneg
        x,y,z,t = self.xyzt()

        if self.cofactor==8:
            u1    = mneg*(z+y)*(z-y)
            u2    = x*y # = t*z
            isr   = isqrt(u1*u2^2)
            i1    = isr*u1 # sqrt(mneg*(z+y)*(z-y))/(x*y)
            i2    = isr*u2 # 1/sqrt(a*(y+z)*(y-z))
            z_inv = i1*i2*t # 1/z

            if negative(t*z_inv):
                if a==-1:
                    x,y = y*self.i,x*self.i
                    den_inv = self.magic * i1
                else:
                    x,y = -y,x
                    den_inv = self.i * self.magic * i1

            else:
                den_inv = i2

            if negative(x*z_inv): y = -y
            s = (z-y) * den_inv
        else:
            num   = mneg*(z+y)*(z-y)
            isr   = isqrt(num*y^2)
            if negative(isr^2*num*y*t): y = -y
            s = isr*y*(z-y)

        return self.gfToBytes(s,mustBePositive=True)

    @classmethod
    def decode(cls,s):
        """Decode, optimized version"""
        s = cls.bytesToGf(s,mustBePositive=True)

        a,d = cls.a,cls.d
        yden     = 1-a*s^2
        ynum     = 1+a*s^2
        yden_sqr = yden^2
        xden_sqr = a*d*ynum^2 - yden_sqr

        isr = isqrt(xden_sqr * yden_sqr)

        xden_inv = isr * yden
        yden_inv = xden_inv * isr * xden_sqr

        x = 2*s*xden_inv
        if negative(x): x = -x
        y = ynum * yden_inv

        if cls.cofactor==8 and (negative(x*y) or y==0):
            raise InvalidEncodingException("x*y is invalid: %d, %d" % (x,y))

        return cls(x,y)

    @classmethod
    def fromJacobiQuartic(cls,s,t,sgn=1):
        """Convert point from its Jacobi Quartic representation"""
        a,d = cls.a,cls.d
        assert s^4 - 2*cls.a*(1-2*d/(d-a))*s^2 + 1 == t^2
        x = 2*s*cls.magic / t
        y = (1+a*s^2) / (1-a*s^2)
        return cls(sgn*x,y)

    @classmethod
    def map(cls, r0):
        a,d = cls.a,cls.d
        r0 = cls.bytesToGf(r0,mustBeProper=False,maskHiBits=True)
        r = cls.qnr * r0^2
        den = (d*r-a)*(a*r-d)
        num = cls.a*(r+1)*(a+d)*(d-a)

        iss,isri = isqrt_i(num*den)
        if iss: sgn,twiddle =  1,1
        else:   sgn,twiddle = -1,r0*cls.qnr
        isri *= twiddle
        s = isri*num
        t = -sgn*isri*s*(r-1)*(d+a)^2 - 1
        if negative(s) == iss: s = -s
        return cls.fromJacobiQuartic(s,t)

class Ed25519Point(RistrettoPoint):
    F = GF(2^255-19)
    P = F.order()
    order = 2^252 + 27742317777372353535851937790883648493
    d = F(-121665/121666)
    a = F(-1)
    i = sqrt(F(-1))
    mneg = F(1)
    qnr = i
    magic = isqrt(a*d-1)
    cofactor = 8
    encLen = 32

    @classmethod
    def base(cls):
        return cls( 15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960
        )

class Ed448GoldilocksPoint(DecafPoint):
    F = GF(2^448-2^224-1)
    P = F.order()
    order = 2^446-13818066809895115352007386748515426880336692474882178609894547503885
    d = F(-39081)
    a = F(1)
    qnr = -1
    cofactor = 4
    encLen = 56
    isoD = F(39082/39081)
    isoMagic = isqrt(a*isoD-1)

    @classmethod
    def base(cls):
        return 2*cls(
 224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710, 298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660
        )

def testVectorsRistretto(cls):
    print("Testing with test Vectors on %s" % cls.__name__)
    P = cls.base()
    Q = cls(0)
    R = bytearray(32)
    for i in range(16):
        assert Q.encode() == R
        Q += P
        R = bytearray(Q.encode())

def testVectorsDecaf(cls):
    print("Testing with test Vectors on %s" % cls.__name__)
    P = cls.base()
    Q = cls(0)
    R = bytearray(56)
    for i in range(16):
        assert Q.encode() == R
        Q += P
        R = bytearray(Q.encode())

def testMapRistretto(cls,n):
    print ("Testing map on %s" % cls.__name__)
    for i in range(n):
        r = randombytes(cls.encLen)
        P = cls.map(r)

testVectorsRistretto(Ed25519Point)
testVectorsDecaf(Ed448GoldilocksPoint)
testMapRistretto(Ed25519Point, 15)
