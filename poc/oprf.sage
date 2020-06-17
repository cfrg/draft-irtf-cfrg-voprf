#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib
import binascii

from hash_to_field import I2OSP

try:
    from sagelib.suite_p256 import p256_sswu_ro, p256_order, p256_p, p256_F, p256_A, p256_B
    from sagelib.suite_p384 import p384_sswu_ro, p384_order, p384_p, p384_F, p384_A, p384_B
    from sagelib.suite_p521 import p521_sswu_ro, p521_order, p521_p, p521_F, p521_A, p521_B
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

if sys.version_info[0] == 3:
    xrange = range
    _as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
    _strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
else:
    _as_bytes = lambda x: x
    _strxor = lambda str1, str2: ''.join( chr(ord(s1) ^ ord(s2)) for (s1, s2) in zip(str1, str2) )

def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, bytes)
    return "0x" + "".join("{:02x}".format(c) for c in octet_string)


class Group(object):
	def __init__(self, name):
		self.name = name

	def order(self):
		return 0

	def generator(self):
		return 0

	def random_scalar(self):
		return None

	def identity(self):
		return 0

	def serialize(self, element):
		return None

	def deserialize(self, encoded):
		return None

	def hash_to_group(self, encoded):
		return None

	def __str__(self):
		return self.name

class GroupNISTCurve(Group):
	def __init__(self, name, suite, F, A, B, p, order, gx, gy):
		Group.__init__(self, name)
		self.F = F
		EC = EllipticCurve(F, [F(A), F(B)])
		self.curve = EC
		self.gx = gx
		self.gy = gy
		self.p = p
		self.order = order
		self.h2c_suite = suite
		self.G = EC(F(gx), F(gy))

	def suite_name(self):
		return self.name

	def order(self):
		return self.order

	def generator(self):
		return self.G

	def random_scalar(self):
		return self.F.random_element()

	def identity(self):
		return self.curve.random_element() * self.order()

	def serialize(self, element):
		x, y = element[0], element[1]
		L = int(((log(self.p, 2) + 8) / 8).n())
		return I2OSP(4, 1) + I2OSP(x, L) + I2OSP(y, L)

	def deserialize(self, encoded):
		# 0x04 || x || y
		assert(encoded[0] == 0x04) 
		assert(len(encoded) % 2 != 0)
		element_length = (len(encoded) - 1) / 2
		x = OS2IP(encoded[1:element_length+1])
		y = OS2IP(encoded[1+element_length:])
		return self.EC(F(x), F(y))

	def hash_to_group(self, msg, dst):
		self.h2c_suite.dst = dst
		return self.h2c_suite(msg)

class GroupP256(GroupNISTCurve):
	def __init__(self):
		# See FIPS 186-3, section D.2.3
		gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
		gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
		GroupNISTCurve.__init__(self, "P256_XMD:SHA-512_SSWU_RO_", p256_sswu_ro, p256_F, p256_A, p256_B, p256_p, p256_order, gx, gy)

class GroupP384(GroupNISTCurve):
	def __init__(self):
		# See FIPS 186-3, section D.2.4
		gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
		gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
		GroupNISTCurve.__init__(self, "P384_XMD:SHA-512_SSWU_RO_", p384_sswu_ro, p384_F, p384_A, p384_B, p384_p, p384_order, gx, gy)

class GroupP521(GroupNISTCurve):
	def __init__(self):
		# See FIPS 186-3, section D.2.5
		gx = 0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66
		gy = 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650
		GroupNISTCurve.__init__(self, "P521_XMD:SHA-512_SSWU_RO_", p521_sswu_ro, p521_F, p521_A, p521_B, p521_p, p521_order, gx, gy)


class Ciphersuite(object):
	def __init__(self, name, group, H1):
		self.name = name
		self.group = group
		self.H1 = H1

	def __str__(self):
		return self.name

class VerifiableCiphersuite(Ciphersuite):
	def __init__(self, name, group, H1, H2, H3):
		Ciphersuite.__init__(self, name, group, H1)
		self.H2 = H2
		self.H3 = H3


class Client(object):
	def __init__(self, suite):
		self.suite = suite
		self.dst = _as_bytes("RFCXXXX-VOPRF-" + self.suite.group.suite_name())

	def blind(self, x):
		r = ZZ(self.suite.group.random_scalar())
		P = self.suite.group.hash_to_group(x, self.dst)
		X = r * P
		return r, X, P

	def unblind(self, N, r):
		r_inv = inverse_mod(r, self.suite.group.G.order())
		y = r_inv * N
		return y

	def finalize(self, x, y, info):
		h = self.suite.H1()

		finalize_dst = _as_bytes("RFCXXXX-Finalize")
		encoded_point = self.suite.group.serialize(y)

		h.update(I2OSP(len(x), 2))
		h.update(x)
		h.update(I2OSP(len(encoded_point), 2))
		h.update(encoded_point)
		h.update(I2OSP(len(info), 2))
		h.update(info)
		h.update(I2OSP(len(finalize_dst), 2))
		h.update(finalize_dst)

		return h.digest()

class Server(object):
	def __init__(self, suite):
		self.suite = suite
		self.k = ZZ(self.suite.group.random_scalar())

	def set_key(self, k):
		self.k = k

	def evaluate(self, element):
		return self.k * element


class Protocol(object):
	def __init__(self):
		self.inputs = map(lambda h : _as_bytes(bytearray.fromhex(h).decode()), ['00', '01', '02'])

	def run_vector(self, vector):
		raise Exception("Not implemented")

	def run(self, client, server, info):
		assert(client.suite.group == server.suite.group)
		group = client.suite.group

		vectors = []
		for x in self.inputs:
			r, R, P = client.blind(x)
			T = server.evaluate(R)
			Z = client.unblind(T, r)
			y = client.finalize(x, Z, info)

			vector = {}
			vector["x"] = to_hex(x)
			vector["P"] = to_hex(group.serialize(P))
			vector["R"] = to_hex(group.serialize(R))
			vector["T"] = to_hex(group.serialize(T))
			vector["Z"] = to_hex(group.serialize(Z))
			vector["y"] = to_hex(y)
			vectors.append(vector)

		vector = {}
		vector["k"] = hex(server.k)
		vector["info"] = info
		vector["suite"] = client.suite.name
		vector["vectors"] = vectors

		return vector

ciphersuites = {
	Ciphersuite("OPRF-P256-HKDF-SHA512-SSWU-RO", GroupP256(), hashlib.sha512),
	Ciphersuite("OPRF-P384-HKDF-SHA512-SSWU-RO", GroupP384(), hashlib.sha512),
	Ciphersuite("OPRF-P521-HKDF-SHA512-SSWU-RO", GroupP521(), hashlib.sha512),
}

def main():
	vectors = {}
	for suite in ciphersuites:
		client = Client(suite)
		server = Server(suite)
		protocol = Protocol()
		vectors[suite.name] = protocol.run(client, server, "test information")

	print(json.dumps(vectors))

if __name__ == "__main__":
    # fixed_voprf()
    main()
