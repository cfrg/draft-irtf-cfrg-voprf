#!/usr/bin/sage
# vim: syntax=python

import sys
import json

try:
    from sagelib.oprf import SetupBaseServer, SetupBaseClient, SetupVerifiableServer, SetupVerifiableClient, oprf_ciphersuites, _as_bytes
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

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

    def run(self, client, server, info):
        assert(client.suite.group == server.suite.group)
        group = client.suite.group

        vectors = []
        for x in self.inputs:
            r, R, P = client.blind(x)
            T = server.evaluate(R)
            Z = client.unblind(T, r, R)
            y = client.finalize(x, Z, info.encode("utf-8"))

            vector = {}
            vector["ClientInput"] = to_hex(x)
            vector["UnblindedElement"] = to_hex(group.serialize(P))
            vector["BlindedElement"] = to_hex(group.serialize(R))
            vector["Evaluation"] = {
                "EvaluatedElement": to_hex(group.serialize(T[0])),
            }
            if len(T) == 2 and T[1] != None:
                vector["Evaluation"]["proof"] = {
                    "c": hex(T[1][0]),
                    "s": hex(T[1][1]),
                }

            vector["SignedElement"] = to_hex(group.serialize(Z))
            vector["ClientOutput"] = to_hex(y)
            vectors.append(vector)

        vector = {}
        vector["skS"] = hex(server.skS)
        vector["info"] = info
        vector["suite"] = client.suite.name
        vector["vectors"] = vectors

        return vector

def main():
    vectors = {}

    for suite in oprf_ciphersuites:
        server = SetupBaseServer(suite)
        client = SetupBaseClient(suite)
        protocol = Protocol()
        vectors["Base" + suite.name] = protocol.run(client, server, "test information")

    for suite in oprf_ciphersuites:
        server, pkS = SetupVerifiableServer(suite)
        client = SetupVerifiableClient(suite, pkS)
        protocol = Protocol()
        vectors["Verifiable" + suite.name] = protocol.run(client, server, "test information")

    print(json.dumps(vectors))

if __name__ == "__main__":
    main()
