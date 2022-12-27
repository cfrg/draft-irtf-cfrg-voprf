#!/usr/bin/sage
# vim: syntax=python

"""Exemplifies a run of the VOPRF protocol"""

import os
import sys

try:
    from sagelib.test_drng import TestDRNG
    from sagelib.oprf \
    import DeriveKeyPair, SetupVOPRFServer, SetupVOPRFClient, MODE_VOPRF, \
           oprf_ciphersuites, ciphersuite_p256_sha256

except ImportError as err:
    sys.exit("Try running `make setup && make clean pyfiles`. Full error: " + err)

to_hex = lambda x: "".join(["{:02x}".format(i) for i in x])

if __name__ == "__main__":
    # Offline Setup
    rng = TestDRNG('prng-seed'.encode('utf-8'))
    suite = oprf_ciphersuites[ciphersuite_p256_sha256]
    Ns = suite.group.scalar_byte_length()
    info = b'info specific for this key'
    seed = os.urandom(Ns)
    skS, pkS = DeriveKeyPair(MODE_VOPRF, suite, seed, info)

    client = SetupVOPRFClient(suite, pkS)
    server = SetupVOPRFServer(suite, skS, pkS)

    # Online Protocol
    #
    #   Client(pkS)                                       Server(skS,pkS)
    # -------------------------------------------------------------------
    # blind, blindedElement = Blind(input)
    input = b'alice in wonderland'
    blind, blinded_element = client.blind(input, rng)
    #                            blindedElement
    #                              ---------->
    #
    #            evaluatedElement, proof = BlindEvaluate(blindedElement)
    evaluated_element, proof, _ = server.blind_evaluate(blinded_element, rng)
    #                            <----------
    #
    # output = Finalize(input, blind, evaluatedElement,
    #                   blindedElement, proof)
    output = client.finalize(input, blind, evaluated_element, blinded_element, proof)
    print("mode:", "VOPRF")
    print("suite:", suite.name)
    print("input:", to_hex(input))
    print("output:", to_hex(output))
