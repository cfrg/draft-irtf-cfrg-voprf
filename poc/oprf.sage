#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import hashlib
import binascii

from collections import namedtuple

from hash_to_field import I2OSP

try:
    from sagelib.groups import GroupP256, GroupP384, GroupP521, GroupRistretto255, GroupDecaf448
    from sagelib.suite_p256 import p256_sswu_ro, p256_order, p256_p, p256_F, p256_A, p256_B
    from sagelib.suite_p384 import p384_sswu_ro, p384_order, p384_p, p384_F, p384_A, p384_B
    from sagelib.suite_p521 import p521_sswu_ro, p521_order, p521_p, p521_F, p521_A, p521_B
    from sagelib.common import sgn0
    from sagelib.ristretto_decaf import Ed25519Point, Ed448GoldilocksPoint
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

if sys.version_info[0] == 3:
    xrange = range
    _as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
    _strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
else:
    _as_bytes = lambda x: x
    _strxor = lambda str1, str2: ''.join( chr(ord(s1) ^ ord(s2)) for (s1, s2) in zip(str1, str2) )

class Context(object):
    def __init__(self, version, mode, suite):
        self.mode = mode
        self.suite = suite
        self.context_string = _as_bytes(version) + I2OSP(self.mode, 1) + I2OSP(self.suite.identifier, 2)

    def group_domain_separation_tag(self):
        return _as_bytes("HashToGroup-") + self.context_string

    def scalar_domain_separation_tag(self):
        return _as_bytes("HashToScalar-") + self.context_string

    def domain_separation_tag(self, prefix):
        return _as_bytes(prefix) + self.context_string

class Evaluation(object):
    def __init__(self, evaluated_element, proof):
        self.evaluated_element = evaluated_element
        self.proof = proof

class OPRFClientContext(Context):
    def __init__(self, version, mode, suite):
        Context.__init__(self, version, mode, suite)

    def identifier(self):
        return self.identifier

    def blind(self, x):
        blind = ZZ(self.suite.group.random_scalar())
        P = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        if P == self.suite.group.identity():
            raise Exception("InvalidInputError")
        blinded_element = blind * P
        return blind, blinded_element

    def unblind(self, blind, evaluated_element, blinded_element, proof):
        blind_inv = inverse_mod(blind, self.suite.group.order())
        N = blind_inv * evaluated_element
        unblinded_element = self.suite.group.serialize(N)
        return unblinded_element

    def finalize(self, x, blind, evaluated_element, blinded_element, proof, info):
        unblinded_element = self.unblind(blind, evaluated_element, blinded_element, proof)
        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(unblinded_element), 2) + unblinded_element \
            + _as_bytes("Finalize")

        return self.suite.hash(finalize_input)

class OPRFServerContext(Context):
    def __init__(self, version, mode, suite, skS, pkS):
        Context.__init__(self, version, mode, suite)
        self.skS = skS
        self.pkS = pkS

    def evaluate(self, blinded_element, info):
        evaluated_element = self.skS * blinded_element
        return evaluated_element, None, None

    def verify_finalize(self, x, expected_digest, info):
        P = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        evaluated_element, _, _ = self.evaluate(P, info) # Ignore proof output
        issued_element = self.suite.group.serialize(evaluated_element)

        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(issued_element), 2) + issued_element \
            + _as_bytes("Finalize")

        digest = self.suite.hash(finalize_input)

        return (digest == expected_digest)

class Verifiable(object):
    def compute_composites_inner(self, k, B, Cs, Ds):
        assert(len(Cs) == len(Ds))

        seedDST = _as_bytes("Seed-") + self.context_string
        Bm = self.suite.group.serialize(B)

        h1_input = I2OSP(len(Bm), 2) + Bm \
            + I2OSP(len(seedDST), 2) + seedDST
        seed = self.suite.hash(h1_input)

        M = self.suite.group.identity()
        Z = self.suite.group.identity()

        for i in range(len(Cs)):
            Ci = self.suite.group.serialize(Cs[i])
            Di = self.suite.group.serialize(Ds[i])
            h2_input = I2OSP(len(seed), 2) + seed \
                + I2OSP(i, 2) \
                + I2OSP(len(Ci), 2) + Ci \
                + I2OSP(len(Di), 2) + Di \
                + _as_bytes("Composite")

            di = self.suite.group.hash_to_scalar(h2_input, self.scalar_domain_separation_tag())
            M = (di * Cs[i]) + M

            if k == None:
                Z = (di * Ds[i]) + Z

        if k != None:
            Z = k * M

        return [M, Z]

    def compute_composites_fast(self, k, B, Cs, Ds):
        return self.compute_composites_inner(k, B, Cs, Ds)

    def compute_composites(self, B, Cs, Ds):
        return self.compute_composites_inner(None, B, Cs, Ds)

class VOPRFClientContext(OPRFClientContext,Verifiable):
    def __init__(self, version, mode, suite, pkS):
        OPRFClientContext.__init__(self, version, mode, suite)
        self.pkS = pkS

    def verify_proof(self, A, B, Cs, Ds, proof):
        a = self.compute_composites(B, Cs, Ds)

        M = a[0]
        Z = a[1]
        t2 = (proof[1] * A) + (proof[0] * B)
        t3 = (proof[1] * M) + (proof[0] * Z)

        Bm = self.suite.group.serialize(B)
        a0 = self.suite.group.serialize(M)
        a1 = self.suite.group.serialize(Z)
        a2 = self.suite.group.serialize(t2)
        a3 = self.suite.group.serialize(t3)

        h2s_input = I2OSP(len(Bm), 2) + Bm \
            + I2OSP(len(a0), 2) + a0 \
            + I2OSP(len(a1), 2) + a1 \
            + I2OSP(len(a2), 2) + a2 \
            + I2OSP(len(a3), 2) + a3 \
            + _as_bytes("Challenge")

        c = self.suite.group.hash_to_scalar(h2s_input, self.scalar_domain_separation_tag())

        assert(c == proof[0])
        return c == proof[0]

    def unblind(self, blind, evaluated_element, blinded_element, proof):
        G = self.suite.group.generator()
        if not self.verify_proof(G, self.pkS, [blinded_element], [evaluated_element], proof):
            raise Exception("VerifyError")

        blind_inv = inverse_mod(blind, self.suite.group.order())
        N = blind_inv * evaluated_element
        unblinded_element = self.suite.group.serialize(N)
        return unblinded_element

    def unblind_batch(self, blinds, evaluated_elements, blinded_elements, proof):
        assert(len(blinds) == len(evaluated_elements))
        assert(len(evaluated_elements) == len(blinded_elements))

        G = self.suite.group.generator()
        if not self.verify_proof(G, self.pkS, blinded_elements, evaluated_elements, proof):
            raise Exception("VerifyError")

        unblinded_elements = []
        for i, evaluated_element in enumerate(evaluated_elements):
            blind_inv = inverse_mod(blinds[i], self.suite.group.order())
            N = blind_inv * evaluated_element
            unblinded_element = self.suite.group.serialize(N)
            unblinded_elements.append(unblinded_element)

        return unblinded_elements

    def finalize(self, x, blind, evaluated_element, blinded_element, proof, info):
        unblinded_element = self.unblind(blind, evaluated_element, blinded_element, proof)
        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(unblinded_element), 2) + unblinded_element \
            + _as_bytes("Finalize")

        return self.suite.hash(finalize_input)

    def finalize_batch(self, xs, blinds, evaluated_elements, blinded_elements, proof, info):
        assert(len(blinds) == len(evaluated_elements))
        assert(len(evaluated_elements) == len(blinded_elements))

        unblinded_elements = self.unblind_batch(blinds, evaluated_elements, blinded_elements, proof)

        outputs = []
        for i, unblinded_element in enumerate(unblinded_elements):
            finalize_input = I2OSP(len(xs[i]), 2) + xs[i] \
                + I2OSP(len(unblinded_element), 2) + unblinded_element \
                + _as_bytes("Finalize")

            digest = self.suite.hash(finalize_input)
            outputs.append(digest)

        return outputs

class VOPRFServerContext(OPRFServerContext,Verifiable):
    def __init__(self, version, mode, suite, skS, pkS):
        OPRFServerContext.__init__(self, version, mode, suite, skS, pkS)

    def generate_proof(self, k, A, B, Cs, Ds):
        a = self.compute_composites_fast(k, B, Cs, Ds)

        r = ZZ(self.suite.group.random_scalar())
        M = a[0]
        Z = a[1]
        t2 = r * A
        t3 = r * M

        Bm = self.suite.group.serialize(B)
        a0 = self.suite.group.serialize(M)
        a1 = self.suite.group.serialize(Z)
        a2 = self.suite.group.serialize(t2)
        a3 = self.suite.group.serialize(t3)

        h2s_input = I2OSP(len(Bm), 2) + Bm \
            + I2OSP(len(a0), 2) + a0 \
            + I2OSP(len(a1), 2) + a1 \
            + I2OSP(len(a2), 2) + a2 \
            + I2OSP(len(a3), 2) + a3 \
            + _as_bytes("Challenge")

        c = self.suite.group.hash_to_scalar(h2s_input, self.scalar_domain_separation_tag())
        s = (r - c * k) % self.suite.group.order()

        return [c, s], r

    def evaluate(self, blinded_element, info):
        evaluated_element = self.skS * blinded_element
        proof, r = self.generate_proof(self.skS, self.suite.group.generator(), self.pkS, [blinded_element], [evaluated_element])
        return evaluated_element, proof, r

    def evaluate_batch(self, blinded_elements, info):
        evaluated_elements = []
        for blinded_element in blinded_elements:
            evaluated_element = self.skS * blinded_element
            evaluated_elements.append(evaluated_element)

        proof, r = self.generate_proof(self.skS, self.suite.group.generator(), self.pkS, blinded_elements, evaluated_elements)
        return evaluated_elements, proof, r

class POPRFClientContext(VOPRFClientContext):
    def __init__(self, version, mode, suite, pkS):
        VOPRFClientContext.__init__(self, version, mode, suite, pkS)
        self.pkS = pkS

    def blind(self, x, info):
        context = _as_bytes("Info") + I2OSP(len(info), 2) + info
        t = self.suite.group.hash_to_scalar(context, self.scalar_domain_separation_tag())
        G = self.suite.group.generator()
        tweaked_key = (G * t) + self.pkS
        if tweaked_key == self.suite.group.identity():
            raise Exception("InvalidInputError")

        blind = ZZ(self.suite.group.random_scalar())
        P = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        if P == self.suite.group.identity():
            raise Exception("InvalidInputError")

        blinded_element = blind * P
        return blind, blinded_element, tweaked_key

    def unblind(self, blind, evaluated_element, blinded_element, proof, tweaked_key):
        G = self.suite.group.generator()
        if not self.verify_proof(G, tweaked_key, [evaluated_element], [blinded_element], proof):
            raise Exception("Proof verification failed")

        blind_inv = inverse_mod(blind, self.suite.group.order())
        N = blind_inv * evaluated_element
        unblinded_element = self.suite.group.serialize(N)
        return unblinded_element

    def unblind_batch(self, blinds, evaluated_elements, blinded_elements, proof, tweaked_key):
        assert(len(blinds) == len(evaluated_elements))
        assert(len(evaluated_elements) == len(blinded_elements))

        G = self.suite.group.generator()
        if not self.verify_proof(G, tweaked_key, evaluated_elements, blinded_elements, proof):
            raise Exception("Proof verification failed")

        unblinded_elements = []
        for i, evaluated_element in enumerate(evaluated_elements):
            blind_inv = inverse_mod(blinds[i], self.suite.group.order())
            N = blind_inv * evaluated_element
            unblinded_element = self.suite.group.serialize(N)
            unblinded_elements.append(unblinded_element)

        return unblinded_elements

    def finalize(self, x, blind, evaluated_element, blinded_element, proof, info, tweaked_key):
        unblinded_element = self.unblind(blind, evaluated_element, blinded_element, proof, tweaked_key)
        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(info), 2) + info \
            + I2OSP(len(unblinded_element), 2) + unblinded_element \
            + _as_bytes("Finalize")

        return self.suite.hash(finalize_input)

    def finalize_batch(self, xs, blinds, evaluated_elements, blinded_elements, proof, info, tweaked_key):
        assert(len(blinds) == len(evaluated_elements))
        assert(len(evaluated_elements) == len(blinded_elements))

        unblinded_elements = self.unblind_batch(blinds, evaluated_elements, blinded_elements, proof, tweaked_key)

        outputs = []
        for i, unblinded_element in enumerate(unblinded_elements):
            finalize_input = I2OSP(len(xs[i]), 2) + xs[i] \
                + I2OSP(len(info), 2) + info \
                + I2OSP(len(unblinded_element), 2) + unblinded_element \
                + _as_bytes("Finalize")

            digest = self.suite.hash(finalize_input)
            outputs.append(digest)

        return outputs

class POPRFServerContext(VOPRFServerContext):
    def __init__(self, version, mode, suite, skS, pkS):
        VOPRFServerContext.__init__(self, version, mode, suite, skS, pkS)

    def evaluate(self, blinded_element, info):
        context = _as_bytes("Info") + I2OSP(len(info), 2) + info
        t = self.suite.group.hash_to_scalar(context, self.scalar_domain_separation_tag())
        k = self.skS + t
        if int(k) == 0:
            raise Exception("InverseError")
        k_inv = inverse_mod(k, self.suite.group.order())
        evaluated_element = k_inv * blinded_element

        G = self.suite.group.generator()
        U = k * G
        proof, r = self.generate_proof(k, G, U, [evaluated_element], [blinded_element])
        return evaluated_element, proof, r

    def evaluate_batch(self, blinded_elements, info):
        context = _as_bytes("Info") + I2OSP(len(info), 2) + info
        t = self.suite.group.hash_to_scalar(context, self.scalar_domain_separation_tag())

        evaluated_elements = []
        for blinded_element in blinded_elements:
            k = self.skS + t
            if int(k) == 0:
                raise Exception("InverseError")
            k_inv = inverse_mod(k, self.suite.group.order())
            evaluated_element = k_inv * blinded_element
            evaluated_elements.append(evaluated_element)

        G = self.suite.group.generator()
        U = k * G
        proof, r = self.generate_proof(k, G, U, evaluated_elements, blinded_elements)
        return evaluated_elements, proof, r

    def verify_finalize(self, x, expected_digest, info):
        P = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        evaluated_element, _, _ = self.evaluate(P, info) # Ignore proof output
        issued_element = self.suite.group.serialize(evaluated_element)

        finalize_input = I2OSP(len(x), 2) + x \
            + I2OSP(len(info), 2) + info \
            + I2OSP(len(issued_element), 2) + issued_element \
            + _as_bytes("Finalize")

        digest = self.suite.hash(finalize_input)

        return (digest == expected_digest)

MODE_OPRF = 0x00
MODE_VOPRF = 0x01
MODE_POPRF = 0x02

VERSION = "VOPRF09-"

def DeriveKeyPair(mode, suite, seed, info):
    ctx = Context(VERSION, mode, suite)
    deriveInput = seed + I2OSP(len(info), 2) + info
    counter = 0
    skS = ZZ(0)
    while ZZ(skS) == ZZ(0):
        if counter > 255:
            raise Exception("DeriveKeyPairError")
        hashInput = deriveInput + I2OSP(counter, 1)
        skS = suite.group.hash_to_scalar(hashInput, ctx.domain_separation_tag("DeriveKeyPair"))
        counter = counter + 1
    pkS = skS * suite.group.generator()
    return skS, pkS

def SetupOPRFServer(suite, skS):
    return OPRFServerContext(VERSION, MODE_OPRF, suite, skS, None)

def SetupOPRFClient(suite):
    return OPRFClientContext(VERSION, MODE_OPRF, suite)

def SetupVOPRFServer(suite, skS, pkS):
    return VOPRFServerContext(VERSION, MODE_VOPRF, suite, skS, pkS)

def SetupVOPRFClient(suite, pkS):
    return VOPRFClientContext(VERSION, MODE_VOPRF, suite, pkS)

def SetupPOPRFServer(suite, skS, pkS):
    return POPRFServerContext(VERSION, MODE_POPRF, suite, skS, pkS)

def SetupPOPRFClient(suite, pkS):
    return POPRFClientContext(VERSION, MODE_POPRF, suite, pkS)

Ciphersuite = namedtuple("Ciphersuite", ["name", "identifier", "group", "H", "hash"])

ciphersuite_ristretto255_sha512 = 0x0001
ciphersuite_decaf448_shake256 = 0x0002
ciphersuite_p256_sha256 = 0x0003
ciphersuite_p384_sha384 = 0x0004
ciphersuite_p521_sha512 = 0x0005

oprf_ciphersuites = {
    ciphersuite_ristretto255_sha512: Ciphersuite("OPRF(ristretto255, SHA-512)", ciphersuite_ristretto255_sha512, GroupRistretto255(), hashlib.sha512, lambda x : hashlib.sha512(x).digest()),
    ciphersuite_decaf448_shake256: Ciphersuite("OPRF(decaf448, SHAKE-256)", ciphersuite_decaf448_shake256, GroupDecaf448(), hashlib.shake_256, lambda x : hashlib.shake_256(x).digest(int(64))),
    ciphersuite_p256_sha256: Ciphersuite("OPRF(P-256, SHA-256)", ciphersuite_p256_sha256, GroupP256(), hashlib.sha256, lambda x : hashlib.sha256(x).digest()),
    ciphersuite_p384_sha384: Ciphersuite("OPRF(P-384, SHA-384)", ciphersuite_p384_sha384, GroupP384(), hashlib.sha384, lambda x : hashlib.sha384(x).digest()),
    ciphersuite_p521_sha512: Ciphersuite("OPRF(P-521, SHA-512)", ciphersuite_p521_sha512, GroupP521(), hashlib.sha512, lambda x : hashlib.sha512(x).digest()),
}
