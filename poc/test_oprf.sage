#!/usr/bin/sage
# vim: syntax=python

import sys
import json
import binascii

try:
    from sagelib.oprf                                                       \
    import KeyGen, SetupBaseServer, SetupBaseClient, SetupVerifiableServer, \
           SetupVerifiableClient, oprf_ciphersuites, _as_bytes, mode_base,  \
           mode_verifiable
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, (bytes, bytearray))
    return "0x" + "".join("{:02x}".format(c) for c in octet_string)

class Protocol(object):
    def __init__(self, suite, mode):
        self.inputs = [b'\x00', b'\x5A'*17, b'\xFF'*23]
        self.suite = suite
        self.mode = mode
        skS, pkS = KeyGen(suite)
        if mode == mode_base:
            self.server = SetupBaseServer(suite, skS)
            self.client = SetupBaseClient(suite)
        elif mode == mode_verifiable:
            self.server = SetupVerifiableServer(suite, skS, pkS)
            self.client = SetupVerifiableClient(suite, pkS)
        else:
            raise Exception("bad mode")

    def run(self):
        group = self.client.suite.group
        client = self.client
        server = self.server

        vectors = []
        for x in self.inputs:
            info = "some_info".encode("utf-8") + x
            r, R, P = client.blind(x)
            T = server.evaluate(R)
            Z = client.unblind(T, r, R)
            y = client.finalize(x, Z, info)

            assert(server.verify_finalize(x, info, y))

            vector = {}
            vector["Blind"] = {
                "Token": hex(r),
                "BlindedElement": to_hex(group.serialize(R)),
            }

            vector["Evaluation"] = {
                "EvaluatedElement": to_hex(group.serialize(T.evaluated_element)),
            }

            if self.mode == mode_verifiable:
                vector["Evaluation"]["proof"] = {
                    "c": hex(T.proof[0]),
                    "s": hex(T.proof[1]),
                }

            vector["Unblind"] = {
                "IssuedToken": to_hex(group.serialize(Z)),
            }

            vector["Client"] = {
                "Input": to_hex(x),
                "Info": to_hex(info),
                "Output": to_hex(y),
            }

            vectors.append(vector)

        vecSuite = {}
        vecSuite["suite"] = self.suite.name
        vecSuite["mode"] = int(self.mode)
        vecSuite["hash"] = self.suite.H().name
        vecSuite["skS"] = hex(server.skS)
        if self.mode == mode_verifiable:
            vecSuite["pkS"] = to_hex(group.serialize(server.pkS))
        vecSuite["vectors"] = vectors

        return vecSuite

def main(path="vectors"):
    allVectors = []

    for suite in oprf_ciphersuites:
        for mode in [mode_base, mode_verifiable]:
            protocol = Protocol(suite, mode)
            allVectors.append(protocol.run())

    with open(path + "/allVectors.json", 'wt') as f:
        json.dump(allVectors, f, sort_keys=True, indent=2)
        f.write("\n")

if __name__ == "__main__":
    main()
