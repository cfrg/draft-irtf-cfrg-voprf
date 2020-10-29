#!/usr/bin/sage
# vim: syntax=python

import binascii
class InvalidEncodingException(Exception): pass

def lobit(x): return int(x) & 1
def negative(x): return lobit(x)
def enc_le(x,n): return bytearray([int(x)>>(8*i) & 0xFF for i in range(n)])

def optimized_version_of(spec):
    """Decorator: This function is an optimized version of some specification"""
    def decorator(f):
        def wrapper(self,*args,**kwargs):
            def pr(x):
                if isinstance(x,bytearray): return binascii.hexlify(x)
                else: return str(x)
            try: spec_ans = getattr(self,spec,spec)(*args,**kwargs),None
            except Exception as e: spec_ans = None,e
            try: opt_ans = f(self,*args,**kwargs),None
            except Exception as e: opt_ans = None,e
            if spec_ans[1] is None and opt_ans[1] is not None:
                raise SpecException("Mismatch in %s: spec returned %s but opt threw %s"
                   % (f.__name__,str(spec_ans[0]),str(opt_ans[1])))
            if spec_ans[1] is not None and opt_ans[1] is None:
                raise SpecException("Mismatch in %s: spec threw %s but opt returned %s"
                   % (f.__name__,str(spec_ans[1]),str(opt_ans[0])))
            if spec_ans[0] != opt_ans[0]:
                raise SpecException("Mismatch in %s: %s != %s"
                    % (f.__name__,pr(spec_ans[0]),pr(opt_ans[0])))
            if opt_ans[1] is not None: raise opt_ans[1]
            else: return opt_ans[0]
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

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
    #if negative(s): s=-s
    return 1/s

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

class Decaf_1_1_Point(QuotientEdwardsPoint):
    """Tweaked for compatibility with Ristretto, as in draft"""
    def encodeSpec(self):
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
    def decodeSpec(cls,s):
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

    def toJacobiQuartic(self,toggle_rotation=False,toggle_altx=False,toggle_s=False):
        "Return s,t on jacobi curve"
        a,d = self.a,self.d
        x,y,z,t = self.xyzt()

        if self.cofactor == 8:
            # Cofactor 8 version
            # Simulate IMAGINE_TWIST because that's how libdecaf does it
            x = self.i*x
            t = self.i*t
            a = -a
            d = -d

            # OK, the actual libdecaf code should be here
            num = (z+y)*(z-y)
            den = x*y
            isr = isqrt(num*(a-d)*den^2)

            iden = isr * den * self.isoMagic # 1/sqrt((z+y)(z-y)) = 1/sqrt(1-Y^2) / z
            inum = isr * num # sqrt(1-Y^2) * z / xysqrt(a-d) ~ 1/sqrt(1-ax^2)/z

            if negative(iden*inum*self.i*t^2*(d-a)) != toggle_rotation:
                iden,inum = inum,iden
                fac = x*sqrt(a)
                toggle=(a==-1)
            else:
                fac = y
                toggle=False

            imi = self.isoMagic * self.i
            altx = inum*t*imi
            neg_altx = negative(altx) != toggle_altx
            if neg_altx != toggle: inum =- inum

            tmp = fac*(inum*z + 1)
            s = iden*tmp*imi

            negm1 = (negative(s) != toggle_s) != neg_altx
            if negm1: m1 = a*fac + z
            else:     m1 = a*fac - z

            swap = toggle_s

        else:
            # Much simpler cofactor 4 version
            num = (x+t)*(x-t)
            isr = isqrt(num*(a-d)*x^2)
            ratio = isr*num
            altx = ratio*self.isoMagic

            neg_altx = negative(altx) != toggle_altx
            if neg_altx: ratio =- ratio

            tmp = ratio*z - t
            s = (a-d)*isr*x*tmp

            negx = (negative(s) != toggle_s) != neg_altx
            if negx: m1 = -a*t + x
            else:    m1 = -a*t - x

            swap = toggle_s

        if negative(s): s = -s

        return s,m1,a*tmp,swap

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

    @optimized_version_of("encodeSpec")
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
    @optimized_version_of("decodeSpec")
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

class Ed25519Point(RistrettoPoint):
    F = GF(2^255-19)
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

class Ed448GoldilocksPoint(Decaf_1_1_Point):
    F = GF(2^448-2^224-1)
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

def testVectors(cls,n):
    print( "Testing with test Vectors on %s" % cls.__name__)
    P = cls.base()
    Q = cls(0)
    assert Q.encode() == Q.encode()
    Q += P

testVectors(Ed25519Point,100)
#testVectors(Ed25519Point,100)
