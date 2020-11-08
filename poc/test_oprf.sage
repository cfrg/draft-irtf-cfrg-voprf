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
            vector["Blind"] = hex(r)
            vector["BlindedElement"] = to_hex(group.serialize(R))
            vector["EvaluationElement"] = to_hex(group.serialize(T.evaluated_element))
            vector["UnblindedElement"] = to_hex(group.serialize(Z))

            if self.mode == mode_verifiable:
                vector["EvaluationProof"] = {
                    "c": hex(T.proof[0]),
                    "s": hex(T.proof[1]),
                }

            vector["Input"] = to_hex(x)
            vector["Info"] = to_hex(info)
            vector["Output"] = to_hex(y)

            vectors.append(vector)

        vecSuite = {}
        vecSuite["suite"] = self.suite.name
        vecSuite["mode"] = int(self.mode)
        vecSuite["hash"] = self.suite.H().name.upper()
        vecSuite["skS"] = hex(server.skS)
        if self.mode == mode_verifiable:
            vecSuite["pkS"] = to_hex(group.serialize(server.pkS))
        vecSuite["vectors"] = vectors

        return vecSuite

def wrap_write(fh, arg, *args):
    line_length = 68
    string = arg + " " + " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            fh.write(hunk + "\n")

def write_blob(fh, name, blob):
    wrap_write(fh, name + ' = ' + to_hex(blob))

def write_value(fh, name, value):
    wrap_write(fh, name + ' = ' + value)

def write_base_vector(fh, vector):
    write_value(fh, "skS", vector["skS"])
    fh.write("\n")
    for i, v in enumerate(vector["vectors"]):
        fh.write("#### Test Vector " + str(i+1) + "\n")
        fh.write("\n")
        write_value(fh, "Input", v["Input"])
        write_value(fh, "Blind", v["Blind"])
        write_value(fh, "BlindedElement", v["BlindedElement"])
        write_value(fh, "EvaluationElement", v["EvaluationElement"])
        write_value(fh, "UnblindedElement", v["UnblindedElement"])
        write_value(fh, "Info", v["Info"])
        write_value(fh, "Output", v["Output"])
        fh.write("\n")

def write_verifiable_vector(fh, vector):
    write_value(fh, "skS", vector["skS"])
    write_value(fh, "pkS", vector["pkS"])
    fh.write("\n")
    for i, v in enumerate(vector["vectors"]):
        fh.write("#### Test Vector " + str(i+1) + "\n")
        fh.write("\n")
        write_value(fh, "Input", v["Input"])
        write_value(fh, "Blind", v["Blind"])
        write_value(fh, "BlindedElement", v["BlindedElement"])
        write_value(fh, "EvaluationElement", v["EvaluationElement"])
        write_value(fh, "UnblindedElement", v["UnblindedElement"])
        write_value(fh, "EvaluationProofC", v["EvaluationProof"]["c"])
        write_value(fh, "EvaluationProofS", v["EvaluationProof"]["s"])
        write_value(fh, "Info", v["Info"])
        write_value(fh, "Output", v["Output"])
        fh.write("\n")

def main(path="vectors"):
    allVectors = {}
    for suite in oprf_ciphersuites:
        suiteVectors = {}
        for mode in [mode_base, mode_verifiable]:
            protocol = Protocol(suite, mode)
            suiteVectors[str(mode)] = protocol.run()
        allVectors[suite.name] = suiteVectors
    
    with open(path + "/allVectors.json", 'wt') as f:
        json.dump(allVectors, f, sort_keys=True, indent=2)
        f.write("\n")

    with open(path + "/allVectors.txt", 'wt') as f:
        for suite in allVectors:
            f.write("## " + suite + "\n")
            f.write("\n")
            for mode in allVectors[suite]:
                if mode == str(mode_base):
                    f.write("### Base Mode\n")
                    f.write("\n")
                    write_base_vector(f, allVectors[suite][mode])
                else:
                    f.write("### Verifiable Mode\n")
                    f.write("\n")
                    write_verifiable_vector(f, allVectors[suite][mode])

if __name__ == "__main__":
    main()
