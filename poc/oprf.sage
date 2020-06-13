#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib
import binascii

from hash_to_field import I2OSP

try:
    # from sagelib.suite_p256 import p256_sswu_ro
    from sagelib.suite_p384 import p384_sswu_ro, p384_order, p384_p, p384_F, p384_A, p384_B
    # from sagelib.suite_p521 import p521_sswu_ro
    # from sagelib.suite_secp256k1 import secp256k1_sswu_ro
    # from sagelib.suite_25519 import \
    #     edw25519_sha256_ro,   \
    #     monty25519_sha256_ro, \
    #     edw25519_sha512_ro,   \
    #     monty25519_sha512_ro
    # from sagelib.suite_448 import \
    #     edw448_hash_ro,   \
    #     monty448_hash_ro
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make clean pyfiles`." + e)

if sys.version_info[0] == 3:
    xrange = range
    _as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
    _strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
else:
    _as_bytes = lambda x: x
    _strxor = lambda str1, str2: ''.join( chr(ord(s1) ^ ord(s2)) for (s1, s2) in zip(str1, str2) )


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

class GroupP384(Group):
	def __init__(self):
		Group.__init__(self, "P-384")
		self.F = p384_F
		EC = EllipticCurve(p384_F, [p384_F(p384_A), p384_F(p384_B)])
		# https://safecurves.cr.yp.to/base.html
		gx = 26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087
		gy = 8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871
		self.curve = EC
		self.G = EC(self.F(gx), self.F(gy))

	def suite_name(self):
		return "P384_XMD:SHA-512_SSWU_RO_"

	def order(self):
		return p384_order

	def generator(self):
		return self.G

	def random_scalar(self):
		return p384_F.random_element()

	def identity(self):
		return self.curve.random_element() * self.order()

	def serialize(self, element):
		x, y = element[0], element[1]
		L = ZZ((int(((log(p384_p, 2).n() * 8) + 8) / 8)) / 8)
		return I2OSP(4, 1) + I2OSP(x, L) + I2OSP(y, L)

	def deserialize(self, encoded):
		return None

	def hash_to_group(self, msg, dst):
		p384_sswu_ro.dst = dst
		return p384_sswu_ro(msg)


class ServerConfig(object):
	# TODO(caw): this should include whatever content(s) we want in the configuration structure
	def __init__(self, suite, pkS):
		self.suite = suite
		self.pkS = pkS


class Client(object):
	def __init__(self, group, RO):
		self.group = group
		self.RO = RO
		self.dst = _as_bytes("RFCXXXX-VOPRF-" + group.suite_name())

	def blind(self, x):
		r = ZZ(self.group.random_scalar())
		P = self.group.hash_to_group(x, self.dst)
		X = r * P
		return r, X, P

	def unblind(self, N, r):
		r_inv = inverse_mod(r, self.group.G.order())
		y = r_inv * N
		return y

	def finalize(self, x, y, aux):
		# struct {
		#   opaque dst<0..2^16-1>;
		#   opaque input<0..2^16-1>;
		#   opaque point<0..2^16-1>;
		# } FinalizeInput
		h = self.RO()

		finalize_dst = _as_bytes("oprf_derive_output") # TODO(caw): this needs to change
		encoded_point = self.group.serialize(y)

		h.update(I2OSP(len(finalize_dst), 2))
		h.update(finalize_dst)
		h.update(I2OSP(len(x), 2))
		h.update(x)
		h.update(I2OSP(len(encoded_point), 2))
		h.update(encoded_point)

		return h.digest()


class Server(object):
	def __init__(self, group):
		self.group = group
		self.k = ZZ(self.group.random_scalar())

	def set_key(self, k):
		self.k = k

	def evaluate(self, element):
		return self.k * element

def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, bytes)
    return "0x" + "".join("{:02x}".format(c) for c in octet_string)

class Protocol(object):
	def __init__(self):
		self.inputs = map(lambda h : _as_bytes(bytearray.fromhex(h).decode()), ['00', '01', '02'])

	def run_vector(self, vector):
		raise Exception("Not implemented")

	def run(self, client, server):
		assert(client.group == server.group)
		group = client.group
		aux = "aux"

		vectors = []
		for x in self.inputs:
			r, R, P = client.blind(x)
			T = server.evaluate(R)
			Z = client.unblind(T, r)
			y = client.finalize(x, Z, aux)

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
		vector["aux"] = aux
		# vector["suite"] = client.suite
		vector["vectors"] = vectors

		return vector


def main():
	GG = GroupP384()
	client = Client(GG, hashlib.sha512)
	server = Server(GG)

	protocol = Protocol()
	vectors = protocol.run(client, server)
	print(json.dumps(vectors))


def fixed_voprf():
	x = _as_bytes(bytearray.fromhex('00').decode())
	GG = GroupP384()

	dst = _as_bytes("RFCXXXX-VOPRF-P384_XMD:SHA-512_SSWU_RO_")

	P_expected = bytearray.fromhex("0415d7f4f49f59a0e09ca9fe743f8bbdd7fbe0abb76b10b947f06db1d80f363a6292ae5cc95c0a1f59fca92eb3b9cc4779cc9fed910160cf8c150835393b4ca9c040567228a1b44bfebb426f9ecee0731f2a5be5194bfcefc6339684d5600dc44f")
	P_actual = GG.serialize(GG.hash_to_group(x, dst))
	if P_expected != P_actual:
		print(binascii.hexlify(P_expected))
		print(binascii.hexlify(P_actual))
		assert(P_expected == P_actual)

	# (26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087,
	# 8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871)
	# = (0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
	# 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f)
	# 04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
	# print(binascii.hexlify(GG.serialize(GG.generator())))

	client = Client(GG, hashlib.sha512)
	server = Server(GG)
	k = ZZ("731eb0cbe382f110010d354e3fa36f6512bd056daf3f3d00996ae3ac642edb4726d410db80c2321771a93f0308ded9c9", 16)
	server.set_key(k)

	r, X, _ = client.blind(x)

	# P_expected = bytearray.fromhex("0415d7f4f49f59a0e09ca9fe743f8bbdd7fbe0abb76b10b947f06db1d80f363a6292ae5cc95c0a1f59fca92eb3b9cc4779cc9fed910160cf8c150835393b4ca9c040567228a1b44bfebb426f9ecee0731f2a5be5194bfcefc6339684d5600dc44f")
	# P_actual = GG.serialize(P)
	# print(binascii.hexlify(P_expected))
	# print(binascii.hexlify(P_actual))
	# print(P_expected == P_actual)

	T = server.evaluate(X)
	Z = client.unblind(T, r)
	output = binascii.hexlify(client.finalize(x, Z, "aux"))

	output_hex = b'1bcf7f7b3886ce8a46581116174e27504a86bc4b582a33aeecc59bef9a922beac56febdb930cf54302a890ef6712f29540dcd58a66e262fe5cfd24541efb0264'
	if output != output_hex:
		print(output)
		print(output_hex)
		assert(output == output_hex)

if __name__ == "__main__":
    fixed_voprf()
    main()
