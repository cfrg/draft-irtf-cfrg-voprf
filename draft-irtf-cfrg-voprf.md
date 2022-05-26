---
title: Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups
abbrev: OPRFs
docname: draft-irtf-cfrg-voprf-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: A. Davidson
    name: Alex Davidson
    org: Brave Software
    email: alex.davidson92@gmail.com
 -
    ins: A. Faz-Hernandez
    name: Armando Faz-Hernandez
    org: Cloudflare, Inc.
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: armfazh@cloudflare.com
 -
    ins: N. Sullivan
    name: Nick Sullivan
    org: Cloudflare, Inc.
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: nick@cloudflare.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare, Inc.
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net

normative:
  RFC2119:

informative:
  RFC7748:
  PrivacyPass:
    title: Privacy Pass
    target: https://github.com/privacypass/challenge-bypass-server
    date: false
  BG04:
    title: The Static Diffie-Hellman Problem
    target: https://eprint.iacr.org/2004/306
    date: false
    author:
      -
        ins: D. Brown
        org: Certicom Research
      -
        ins: R. Gallant
        org: Certicom Research
  ChaumPedersen: DOI.10.1007/3-540-48071-4_7
  Cheon06: DOI.10.1007/11761679_1
  FS00:
    title: "How To Prove Yourself: Practical Solutions to Identification and Signature Problems"
    target: https://doi.org/10.1007/3-540-47721-7_12
    date: Dec, 2000
    author:
      -
        ins: A. Fiat
        org: The Weizmann Institute of Science, Israel
      -
        ins: A. Shamir
        org: The Weizmann Institute of Science, Israel
  JKKX16: DOI.10.1109/EuroSP.2016.30
  JKK14: DOI.10.1007/978-3-662-45608-8_13
  SJKS17: DOI.10.1109/ICDCS.2017.64
  TCRSTW21:
    title: A Fast and Simple Partially Oblivious PRF, with Applications
    target: https://eprint.iacr.org/2021/864
    date: false
    author:
      -
        ins: N. Tyagi
        org: Cornell University, USA
      -
        ins: S. Celi
        org: Cloudflare, Portugal
      -
        ins: T. Ristenpart
        org: Cornell Tech, USA
      -
        ins: N. Sullivan
        org: Cloudflare, USA
      -
        ins: S. Tessaro
        org: University of Washington, UK
      -
        ins: C. Wood
        org: Cloudflare, USA
  DGSTV18: DOI.10.1515/popets-2018-0026
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)
  SEC2:
    title: "SEC 2: Recommended Elliptic Curve Domain Parameters"
    target: http://www.secg.org/sec2-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)
  x9.62:
    title: "Public Key Cryptography for the Financial Services Industry: the Elliptic Curve Digital Signature Algorithm (ECDSA)"
    date: Sep, 1998
    seriesinfo:
      "ANSI": X9.62-1998
    author:
      -
        org: ANSI
  keyagreement: DOI.10.6028/NIST.SP.800-56Ar3

--- abstract

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol between
client and server for computing the output of a Pseudorandom Function (PRF).
The server provides the PRF secret key, and the client provides the PRF
input. At the end of the protocol, the client learns the PRF output without
learning anything about the PRF secret key, and the server learns neither
the PRF input nor output. An OPRF can also satisfy a notion of 'verifiability',
called a VOPRF. A VOPRF ensures clients can verify that the server used a
specific private key during the execution of the protocol. A VOPRF can also
be partially-oblivious, called a POPRF. A POPRF allows clients and servers
to provide public input to the PRF computation. This document specifies an OPRF,
VOPRF, and POPRF instantiated within standard prime-order groups, including
elliptic curves.

--- middle

# Introduction

A Pseudorandom Function (PRF) F(k, x) is an efficiently computable
function taking a private key k and a value x as input. This function is
pseudorandom if the keyed function K(\_) = F(k, \_) is indistinguishable
from a randomly sampled function acting on the same domain and range as
K(). An Oblivious PRF (OPRF) is a two-party protocol between a server
and a client, where the server holds a PRF key k and the client holds
some input x. The protocol allows both parties to cooperate in computing
F(k, x) such that the client learns F(k, x) without learning anything
about k; and the server does not learn anything about x or F(k, x).
A Verifiable OPRF (VOPRF) is an OPRF wherein the server also proves
to the client that F(k, x) was produced by the key k corresponding
to the server's public key the client knows. A Partially-Oblivious PRF (POPRF)
is a variant of a VOPRF wherein client and server interact in computing
F(k, x, y), for some PRF F with server-provided key k, client-provided
input x, and public input y, and client receives proof
that F(k, x, y) was computed using k corresponding to the public key
that the client knows. A POPRF with fixed input y is functionally
equivalent to a VOPRF.

OPRFs have a variety of applications, including: password-protected secret
sharing schemes {{JKKX16}}, privacy-preserving password stores {{SJKS17}}, and
password-authenticated key exchange or PAKE {{!I-D.irtf-cfrg-opaque}}.
Verifiable POPRFs are necessary in some applications such as Privacy Pass
{{!I-D.ietf-privacypass-protocol}}. Verifiable POPRFs have also been used for
password-protected secret sharing schemes such as that of {{JKK14}}.

This document specifies OPRF, VOPRF, and POPRF protocols built upon
prime-order groups. The document describes each protocol variant,
along with application considerations, and their security properties.

## Change log

[draft-09](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-09):

- Split syntax for OPRF, VOPRF, and POPRF functionalities.
- Make Blind function fallible for invalid private and public inputs.
- Specify key generation.
- Remove serialization steps from core protocol functions.
- Refactor protocol presentation for clarity.
- Simplify security considerations.
- Update application interface considerations.
- Update test vectors.

[draft-08](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-08):

- Adopt partially-oblivious PRF construction from {{TCRSTW21}}.
- Update P-384 suite to use SHA-384 instead of SHA-512.
- Update test vectors.
- Apply various editorial changes.

[draft-07](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-07):

- Bind blinding mechanism to mode (additive for verifiable mode and
  multiplicative for base mode).
- Add explicit errors for deserialization.
- Document explicit errors and API considerations.
- Adopt SHAKE-256 for decaf448 ciphersuite.
- Normalize HashToScalar functionality for all ciphersuites.
- Refactor and generalize DLEQ proof functionality and domain separation
  tags for use in other protocols.
- Update test vectors.
- Apply various editorial changes.

[draft-06](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-06):

- Specify of group element and scalar serialization.
- Remove info parameter from the protocol API and update domain separation guidance.
- Fold Unblind function into Finalize.
- Optimize ComputeComposites for servers (using knowledge of the private key).
- Specify deterministic key generation method.
- Update test vectors.
- Apply various editorial changes.

[draft-05](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-05):

- Move to ristretto255 and decaf448 ciphersuites.
- Clean up ciphersuite definitions.
- Pin domain separation tag construction to draft version.
- Move key generation outside of context construction functions.
- Editorial changes.

[draft-04](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-04):

- Introduce Client and Server contexts for controlling verifiability and
  required functionality.
- Condense API.
- Remove batching from standard functionality (included as an extension)
- Add Curve25519 and P-256 ciphersuites for applications that prevent
  strong-DH oracle attacks.
- Provide explicit prime-order group API and instantiation advice for
  each ciphersuite.
- Proof-of-concept implementation in sage.
- Remove privacy considerations advice as this depends on applications.

[draft-03](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-03):

- Certify public key during VerifiableFinalize.
- Remove protocol integration advice.
- Add text discussing how to perform domain separation.
- Drop OPRF_/VOPRF_ prefix from algorithm names.
- Make prime-order group assumption explicit.
- Changes to algorithms accepting batched inputs.
- Changes to construction of batched DLEQ proofs.
- Updated ciphersuites to be consistent with hash-to-curve and added
  OPRF specific ciphersuites.

[draft-02](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02):

- Added section discussing cryptographic security and static DH oracles.
- Updated batched proof algorithms.

[draft-01](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-01):

- Updated ciphersuites to be in line with
  https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04.
- Made some necessary modular reductions more explicit.

## Requirements

{::boilerplate bcp14}

## Notation and Terminology

The following functions and notation are used throughout the document.

- For any object `x`, we write `len(x)` to denote its length in bytes.
- For two byte arrays `x` and `y`, write `x || y` to denote their
  concatenation.
- I2OSP(x, xLen): Converts a non-negative integer `x` into a byte array
  of specified length `xLen` as described in {{!RFC8017}}. Note that
  this function returns a byte array in big-endian byte order.

All algorithms and procedures described in this document are laid out
in a Python-like pseudocode. The data types `PrivateInput` and `PublicInput`
are opaque byte strings of arbitrary length no larger than 2^13 octets.

String values such as "DeriveKeyPair", "Seed-", and "Finalize" are ASCII string literals.

The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- OPRF: Oblivious Pseudorandom Function.
- VOPRF: Verifiable Oblivious Pseudorandom Function.
- POPRF: Partially Oblivious Pseudorandom Function.
- Client: Protocol initiator. Learns pseudorandom function evaluation as
  the output of the protocol.
- Server: Computes the pseudorandom function over a private key. Learns
  nothing about the client's input or output.

# Preliminaries

The protocols in this document have two primary dependencies:

- `Group`: A prime-order group implementing the API described below in {{pog}},
  with base point defined in the corresponding reference for each group.
  (See {{ciphersuites}} for these base points.)
- `Hash`: A cryptographic hash function whose output length is `Nh` bytes.

{{ciphersuites}} specifies ciphersuites as combinations of `Group` and `Hash`.

## Prime-Order Group {#pog}

In this document, we assume the construction of an additive, prime-order
group `Group` for performing all mathematical operations. Such groups are
uniquely determined by the choice of the prime `p` that defines the
order of the group. (There may, however, exist different representations
of the group for a single `p`. {{ciphersuites}} lists specific groups which
indicate both order and representation.)

The fundamental group operation is addition `+` with identity element
`I`. For any elements `A` and `B` of the group, `A + B = B + A` is
also a member of the group. Also, for any `A` in the group, there exists an element
`-A` such that `A + (-A) = (-A) + A = I`. Scalar multiplication is
equivalent to the repeated application of the group operation on an
element A with itself `r-1` times, this is denoted as `r*A = A + ... + A`.
For any element `A`, `p*A=I`. Scalar base multiplication is equivalent
to the repeated application of the group operation on the fixed group
generator with itself `r-1` times, and is denoted as `ScalarBaseMult(r)`.
Given two elements A and B, the discrete logarithm problem is to find
an integer k such that B = k*A. Thus, k is the discrete logarithm of
B with respect to the base A.
The set of scalars corresponds to `GF(p)`, a prime field of order p, and are
represented as the set of integers defined by `{0, 1, ..., p-1}`.
This document uses types
`Element` and `Scalar` to denote elements of the group and its set of
scalars, respectively.

We now detail a number of member functions that can be invoked on a
prime-order group.

- Order(): Outputs the order of the group (i.e. `p`).
- Identity(): Outputs the identity element of the group (i.e. `I`).
- HashToGroup(x): A member function of `Group` that deterministically maps
  an array of bytes `x` to an element of `Group`. The map must ensure that,
  for any adversary receiving `R = HashToGroup(x)`, it is
  computationally difficult to reverse the mapping. This function is optionally
  parameterized by a domain separation tag (DST); see {{ciphersuites}}.
- HashToScalar(x): A member function of `Group` that deterministically maps
  an array of bytes `x` to an element in GF(p). This function is optionally
  parameterized by a DST; see {{ciphersuites}}.
- RandomScalar(): A member function of `Group` that chooses at random a
  non-zero element in GF(p).
- ScalarInverse(s): Returns the inverse of input Scalar `s` on `GF(p)`.
- SerializeElement(A): A member function of `Group` that maps a group element
  `A` to a unique byte array `buf` of fixed length `Ne`.
- DeserializeElement(buf): A member function of `Group` that maps a byte
  array `buf` to a group element `A`, or raise a DeserializeError if the
  input is not a valid byte representation of an element.
  See {{input-validation}} for further requirements on input validation.
- SerializeScalar(s): A member function of `Group` that maps a scalar element
  `s` to a unique byte array `buf` of fixed length `Ns`.
- DeserializeScalar(buf): A member function of `Group` that maps a byte
  array `buf` to a scalar `s`, or raise a DeserializeError if the input
  is not a valid byte representation of a scalar.
  See {{input-validation}} for further requirements on input validation.

It is convenient in cryptographic applications to instantiate such
prime-order groups using elliptic curves, such as those detailed in
{{SEC2}}. For some choices of elliptic curves (e.g. those detailed in
{{RFC7748}}, which require accounting for cofactors) there are some
implementation issues that introduce inherent discrepancies between
standard prime-order groups and the elliptic curve instantiation. In
this document, all algorithms that we detail assume that the group is a
prime-order group, and this MUST be upheld by any implementation. That is,
any curve instantiation should be written such that any discrepancies
with a prime-order group instantiation are removed. See {{ciphersuites}}
for advice corresponding to the implementation of this interface for
specific definitions of elliptic curves.

## Discrete Logarithm Equivalence Proofs {#dleq}

A proof of knowledge allows a prover to convince a verifier that some
statement is true. If the prover can generate a proof without interaction
with the verifier, the proof is noninteractive. If the verifier learns
nothing other than whether the statement claimed by the prover is true or
false, the proof is zero-knowledge.

This section describes a noninteractive zero-knowledge proof for discrete
logarithm equivalence (DLEQ). A DLEQ proof demonstrates that two pairs of
group elements have the same discrete logarithm without revealing the
discrete logarithm.

The DLEQ proof resembles the Chaum-Pedersen {{ChaumPedersen}} proof, which
is shown to be zero-knowledge by Jarecki, et al. {{JKK14}} and is
noninteractive after applying the Fiat-Shamir transform {{FS00}}.
Furthermore, Davidson, et al. {{DGSTV18}} showed a proof system for
batching DLEQ proofs that has constant-size proofs with respect to the
number of inputs.
The specific DLEQ proof system presented below follows this latter
construction with two modifications: (1) the transcript used to generate
the seed includes more context information, and (2) the individual challenges
for each element in the proof is derived from a seed-prefixed hash-to-scalar
invocation rather than being sampled from a seeded PRNG.
The description is split into
two sub-sections: one for generating the proof, which is done by servers
in the verifiable protocols, and another for verifying the proof, which is
done by clients in the protocol.

### Proof Generation

Generating a proof is done with the `GenerateProof` function, defined below.
This function takes four Elements, A, B, C, and D, and a single
group Scalar k, and produces a proof that `k*A == B` and `k*C == D`.
The output is a value of type Proof, which is a tuple of two Scalar
values.

~~~
Input:

  Scalar k
  Element A
  Element B
  Element C
  Element D

Output:

  Proof proof

Parameters:

  Group G

def GenerateProof(k, A, B, C, D)
  Cs = [C]
  Ds = [D]
  (M, Z) = ComputeCompositesFast(k, B, Cs, Ds)

  r = G.RandomScalar()
  t2 = r * A
  t3 = r * M

  Bm = G.SerializeElement(B)
  a0 = G.SerializeElement(M)
  a1 = G.SerializeElement(Z)
  a2 = G.SerializeElement(t2)
  a3 = G.SerializeElement(t3)

  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            "Challenge"

  c = G.HashToScalar(h2Input)
  s = (r - c * k) mod G.Order()

  return [c, s]
~~~

The helper function ComputeCompositesFast is as defined below.

~~~
Input:

  Scalar k
  Element B
  Element Cs[m]
  Element Ds[m]

Output:

  Element M
  Element Z

Parameters:

  Group G
  PublicInput contextString

def ComputeCompositesFast(k, B, Cs, Ds):
  Bm = G.SerializeElement(B)
  seedDST = "Seed-" || contextString
  h1Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(seedDST), 2) || seedDST
  seed = Hash(h1Input)

  M = G.Identity()
  for i = 0 to range(m):
    Ci = G.SerializeElement(Cs[i])
    Di = G.SerializeElement(Ds[i])
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(Ci), 2) || Ci ||
              I2OSP(len(Di), 2) || Di ||
              "Composite"

    di = G.HashToScalar(h2Input)
    M = di * Cs[i] + M

  Z = k * M

 return (M, Z)
~~~

When used in the protocol described in {{protocol}}, the parameter `contextString` is
as defined in {{configuration}}.

`ComputeCompositesFast` takes lists of inputs, rather than a single input.
Applications can take advantage of this functionality by invoking `GenerateProof`
on batches of inputs to produce a combined, constant-size proof.
In particular, servers can produce a single, constant-sized proof for N DLEQ inputs,
rather than one proof per DLEQ input. This optimization benefits
clients and servers since it amortizes the cost of proof generation
and bandwidth across multiple requests.

### Proof Verification

Verifying a proof is done with the `VerifyProof` function, defined below.
This function takes four Elements, A, B, C, and D, along with a Proof value
output from `GenerateProof`. It outputs a single boolean value indicating whether
or not the proof is valid for the given DLEQ inputs.

~~~
Input:

  Element A
  Element B
  Element C
  Element D
  Proof proof

Output:

  boolean verified

Parameters:

  Group G

def VerifyProof(A, B, C, D, proof):
  Cs = [C]
  Ds = [D]

  (M, Z) = ComputeComposites(B, Cs, Ds)
  c = proof[0]
  s = proof[1]

  t2 = ((s * A) + (c * B))
  t3 = ((s * M) + (c * Z))

  Bm = G.SerializeElement(B)
  a0 = G.SerializeElement(M)
  a1 = G.SerializeElement(Z)
  a2 = G.SerializeElement(t2)
  a3 = G.SerializeElement(t3)

  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            "Challenge"

  expectedC = G.HashToScalar(h2Input)

  return expectedC == c
~~~

The definition of `ComputeComposites` is given below.

~~~
Input:

  Element B
  Element Cs[m]
  Element Ds[m]

Output:

  Element M
  Element Z

Parameters:

  Group G
  PublicInput contextString

def ComputeComposites(B, Cs, Ds):
  Bm = G.SerializeElement(B)
  seedDST = "Seed-" || contextString
  h1Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(seedDST), 2) || seedDST
  seed = Hash(h1Input)

  M = G.Identity()
  Z = G.Identity()
  for i = 0 to m-1:
    Ci = G.SerializeElement(Cs[i])
    Di = G.SerializeElement(Ds[i])
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(Ci), 2) || Ci ||
              I2OSP(len(Di), 2) || Di ||
              "Composite"

    di = G.HashToScalar(h2Input)
    M = di * Cs[i] + M
    Z = di * Ds[i] + Z

 return (M, Z)
~~~

When used in the protocol described in {{protocol}}, the parameter `contextString` is
as defined in {{configuration}}.

As with the proof generation case, proof verification can be batched. `ComputeComposites`
is defined in terms of a batch of inputs. Implementations can take advantage of this
behavior by also batching inputs to `VerifyProof`, respectively.

# Protocol {#protocol}

In this section, we define three OPRF protocol variants -- a base mode,
verifiable mode, and partially-oblivious mode -- with the following properties.

In the base mode, a client and server interact to compute `output = F(skS, input)`,
where `input` is the client's private input, `skS` is the server's private key,
and `output` is the OPRF output. The client learns `output` and the server learns nothing.
This interaction is shown below.

~~~
    Client                                                Server(skS)
  -------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

                          evaluatedElement = Evaluate(blindedElement)

                             evaluatedElement
                               <----------

  output = Finalize(input, blind, evaluatedElement)
~~~
{: #fig-oprf title="OPRF protocol overview"}

In the verifiable mode, the client additionally receives proof that the server used `skS` in
computing the function. To achieve verifiability, as in the original work of {{JKK14}}, the
server provides a zero-knowledge proof that the key provided as input by the server in
the `Evaluate` function is the same key as it used to produce the server's public key, `pkS`,
which the client receives as input to the protocol. This proof does not reveal the server's
private key to the client. This interaction is shown below.

~~~
    Client(pkS)            <---- pkS ------               Server(skS)
  -------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

                   evaluatedElement, proof = Evaluate(blindedElement)

                         evaluatedElement, proof
                               <----------

  output = Finalize(input, blind, evaluatedElement,
                    blindedElement, proof)
~~~
{: #fig-voprf title="VOPRF protocol overview with additional proof"}

The partially-oblivious mode extends the VOPRF mode such that the client and
server can additionally provide a public input `info` that is used in computing
the pseudorandom function. That is, the client and server interact to compute
`output = F(skS, input, info)`. To support additional public input, the client
and server augment the `pkS` and `skS`, respectively, using the `info` value,
as in {{TCRSTW21}}.

~~~
    Client(pkS, info)        <---- pkS ------       Server(skS, info)
  -------------------------------------------------------------------
  blind, blindedElement, tweakedKey = Blind(input, info)

                             blindedElement
                               ---------->

             evaluatedElement, proof = Evaluate(blindedElement, info)

                         evaluatedElement, proof
                               <----------

  output = Finalize(input, blind, evaluatedElement,
                    blindedElement, proof, info, tweakedKey)
~~~
{: #fig-poprf title="POPRF protocol overview with additional public input"}

Each protocol consists of an offline setup phase and an online phase,
described in {{offline}} and {{online}}, respectively. Configuration details
for the offline phase are described in {{configuration}}.

## Configuration {#configuration}

Each of the three protocol variants are identified with a one-byte value:

| Mode           | Value |
|:===============|:======|
| modeOPRF       | 0x00  |
| modeVOPRF      | 0x01  |
| modePOPRF      | 0x02  |

Additionally, each protocol variant is instantiated with a ciphersuite,
or suite. Each ciphersuite is identified with a two-byte value, referred
to as `suiteID`; see {{ciphersuites}} for the registry of initial values.

The mode and ciphersuite ID values are combined to create a "context string"
used throughout the protocol with the following function:

~~~
def CreateContextString(mode, suiteID):
  return "VOPRF09-" || I2OSP(mode, 1) || I2OSP(suiteID, 2)
~~~

[[RFC editor: please change "VOPRF09" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

## Key Generation and Context Setup {#offline}

In the offline setup phase, both the client and server create a context used
for executing the online phase of the protocol after agreeing on a mode and
ciphersuite value suiteID. The server key pair (`skS`, `pkS`) is generated
using the following function, which accepts a randomly generated seed of length
`Ns` and optional public `info` string. The constant `Ns` corresponds to the
size of a serialized Scalar and is defined in {{pog}}.

~~~
Input:

  opaque seed[Ns]
  PublicInput info

Output:

  Scalar skS
  Element pkS

Parameters:

  Group G
  PublicInput contextString

Errors: DeriveKeyPairError

def DeriveKeyPair(seed, info):
  contextString = CreateContextString(mode, suiteID)
  deriveInput = seed || I2OSP(len(info), 2) || info
  counter = 0
  skS = 0
  while skS == 0:
    if counter > 255:
      raise DeriveKeyPairError
    skS = G.HashToScalar(deriveInput || I2OSP(counter, 1),
                          DST = "DeriveKeyPair" || contextString)
    counter = counter + 1
  pkS = G.ScalarBaseMult(skS)
  return skS, pkS
~~~

The OPRF variant server and client contexts are created as follows:

~~~
def SetupOPRFServer(suiteID, skS):
  contextString = CreateContextString(modeOPRF, suiteID)
  return OPRFServerContext(contextString, skS)

def SetupOPRFClient(suiteID):
  contextString = CreateContextString(modeOPRF, suiteID)
  return OPRFClientContext(contextString)
~~~

The VOPRF variant server and client contexts are created as follows:

~~~
def SetupVOPRFServer(suiteID, skS, pkS):
  contextString = CreateContextString(modeVOPRF, suiteID)
  return VOPRFServerContext(contextString, skS)

def SetupVOPRFClient(suiteID, pkS):
  contextString = CreateContextString(modeVOPRF, suiteID)
  return VOPRFClientContext(contextString, pkS)
~~~

The POPRF variant server and client contexts are created as follows:

~~~
def SetupPOPRFServer(suiteID, skS, pkS):
  contextString = CreateContextString(modePOPRF, suiteID)
  return POPRFServerContext(contextString, skS)

def SetupPOPRFClient(suiteID, pkS):
  contextString = CreateContextString(modePOPRF, suiteID)
  return POPRFClientContext(contextString, pkS)
~~~

## Online Protocol {#online}

In the online phase, the client and server engage in a two message protocol
to compute the protocol output. This section describes the protocol details
for each protocol variant. Throughout each description the following parameters
are assumed to exist:

- G, a prime-order Group implementing the API described in {{pog}}.
- contextString, a PublicInput domain separation tag constructed during context setup as created in {{configuration}}.
- skS and pkS, a Scalar and Element representing the private and public keys configured for client and server in {{offline}}.

Applications serialize protocol messages between client and server for
transmission. Elements and scalars are serialized to byte arrays, and values
of type Proof are serialized as the concatenation of two serialized scalars.
Deserializing these values can fail, in which case the application MUST abort
the protocol with a `DeserializeError` failure.

Applications MUST check that input Element values received over the wire
are not the group identity element. This check is handled after deserializing
Element values; see {{input-validation}} for more information on input
validation.

### OPRF Protocol {#oprf}

The OPRF protocol begins with the client blinding its input, as described
by the `Blind` function below. Note that this function can fail with an
`InvalidInputError` error for certain inputs that map to the group identity
element. Dealing with this failure is an application-specific decision;
see {{errors}}.

~~~
Input:

  PrivateInput input

Output:

  Scalar blind
  Element blindedElement

Parameters:

  Group G

Errors: InvalidInputError

def Blind(input):
  blind = G.RandomScalar()
  P = G.HashToGroup(input)
  if P == G.Identity():
    raise InvalidInputError
  blindedElement = blind * P

  return blind, blindedElement
~~~

Clients store `blind` locally, and send `blindedElement` to the server for evaluation.
Upon receipt, servers process `blindedElement` using the `Evaluate` function described
below.

~~~
Input:

  Element blindedElement

Output:

  Element evaluatedElement

Parameters:

  Scalar skS

def Evaluate(blindedElement):
  evaluatedElement = skS * blindedElement
  return evaluatedElement
~~~

Servers send the output `evaluatedElement` to clients for processing.
Recall that servers may batch multiple client inputs to `Evaluate`.

Upon receipt of `evaluatedElement`, clients process it to complete the
OPRF evaluation with the `Finalize` function described below.

~~~
Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElement

Output:

  opaque output[Nh]

Parameters:

  Group G

def Finalize(input, blind, evaluatedElement):
  N = G.ScalarInverse(blind) * evaluatedElement
  unblindedElement = G.SerializeElement(N)

  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              "Finalize"
  return Hash(hashInput)
~~~

### VOPRF Protocol {#voprf}

The VOPRF protocol begins with the client blinding its input, using the same
`Blind` function as in {{oprf}}. Clients store the output `blind` locally
and send `blindedElement` to the server for evaluation. Upon receipt,
servers process `blindedElement` to compute an evaluated element and DLEQ
proof using the following `Evaluate` function.

~~~
Input:

  Element blindedElement

Output:

  Element evaluatedElement
  Proof proof

Parameters:

  Group G
  Scalar skS
  Element pkS

def Evaluate(blindedElement):
  evaluatedElement = skS * blindedElement
  proof = GenerateProof(skS, G.Generator(), pkS,
                        blindedElement, evaluatedElement)
  return evaluatedElement, proof
~~~

The server sends both `evaluatedElement` and `proof` back to the client.
Upon receipt, the client processes both values to complete the VOPRF computation
using the `Finalize` function below.

~~~
Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElement
  Element blindedElement
  Proof proof

Output:

  opaque output[Nh]

Parameters:

  Group G
  Element pkS

Errors: VerifyError

def Finalize(input, blind, evaluatedElement, blindedElement, proof):
  if VerifyProof(G.Generator(), pkS, blindedElement,
                 evaluatedElement, proof) == false:
    raise VerifyError

  N = G.ScalarInverse(blind) * evaluatedElement
  unblindedElement = G.SerializeElement(N)

  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              "Finalize"
  return Hash(hashInput)
~~~

### POPRF Protocol {#poprf}

The POPRF protocol begins with the client blinding its input, using the
following modified `Blind` function. Note that this function can fail with an
`InvalidInputError` error for certain private inputs that map to the group
identity element, as well as certain public inputs that map to invalid
public keys for server evaluation. Dealing with either failure is an
application-specific decision; see {{errors}}.

~~~
Input:

  PrivateInput input
  PublicInput info

Output:

  Scalar blind
  Element blindedElement
  Element tweakedKey

Parameters:

  Group G
  Element pkS

Errors: InvalidInputError

def Blind(input, info):
  framedInfo = "Info" || I2OSP(len(info), 2) || info
  m = G.HashToScalar(framedInfo)
  T = G.ScalarBaseMult(m)
  tweakedKey = T + pkS
  if tweakedKey == G.Identity():
    raise InvalidInputError

  blind = G.RandomScalar()
  P = G.HashToGroup(input)
  if P == G.Identity():
    raise InvalidInputError

  blindedElement = blind * P

  return blind, blindedElement, tweakedKey
~~~

Clients store the outputs `blind` and `tweakedKey` locally and send `blindedElement` to
the server for evaluation. Upon receipt, servers process `blindedElement` to
compute an evaluated element and DLEQ proof using the following `Evaluate` function.

~~~
Input:

  Element blindedElement
  PublicInput info

Output:

  Element evaluatedElement
  Proof proof

Parameters:

  Group G
  Scalar skS
  Element pkS

Errors: InverseError

def Evaluate(blindedElement, info):
  framedInfo = "Info" || I2OSP(len(info), 2) || info
  m = G.HashToScalar(framedInfo)
  t = skS + m
  if t == 0:
    raise InverseError

  evaluatedElement = G.ScalarInverse(t) * blindedElement

  tweakedKey = G.ScalarBaseMult(t)
  proof = GenerateProof(t, G.Generator(), tweakedKey,
                        evaluatedElement, blindedElement)

  return evaluatedElement, proof
~~~

The server sends both `evaluatedElement` and `proof` back to the client.
Upon receipt, the client processes both values to complete the VOPRF computation
using the `Finalize` function below.

~~~
Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElement
  Element blindedElement
  Proof proof
  PublicInput info
  Element tweakedKey

Output:

  opaque output[Nh]

Parameters:

  Group G
  Element pkS

Errors: VerifyError

def Finalize(input, blind, evaluatedElement, blindedElement,
             proof, info, tweakedKey):
  if VerifyProof(G.Generator(), tweakedKey, evaluatedElement,
                 blindedElement, proof) == false:
    raise VerifyError

  N = G.ScalarInverse(blind) * evaluatedElement
  unblindedElement = G.SerializeElement(N)

  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              "Finalize"
  return Hash(hashInput)
~~~

# Ciphersuites {#ciphersuites}

A ciphersuite (also referred to as 'suite' in this document) for the protocol
wraps the functionality required for the protocol to take place. The
ciphersuite should be available to both the client and server, and agreement
on the specific instantiation is assumed throughout.

A ciphersuite contains instantiations of the following functionalities:

- `Group`: A prime-order Group exposing the API detailed in {{pog}}, with base
  point defined in the corresponding reference for each group. Each group also
  specifies HashToGroup, HashToScalar, and serialization functionalities. For
  HashToGroup, the domain separation tag (DST) is constructed in accordance
  with the recommendations in {{!I-D.irtf-cfrg-hash-to-curve}}, Section 3.1.
  For HashToScalar, each group specifies an integer order that is used in
  reducing integer values to a member of the corresponding scalar field.
- `Hash`: A cryptographic hash function whose output length is Nh bytes long.

This section specifies an initial registry of ciphersuites with supported groups
and hash functions. It also includes implementation details for each ciphersuite,
focusing on input validation, as well as requirements for future ciphersuites.

## Ciphersuite Registry

For each ciphersuite, contextString is that which is computed in the Setup functions.
Applications should take caution in using ciphersuites targeting P-256 and ristretto255.
See {{cryptanalysis}} for related discussion.

### OPRF(ristretto255, SHA-512)

- Group: ristretto255 {{!RISTRETTO=I-D.irtf-cfrg-ristretto255-decaf448}}
  - HashToGroup(): Use hash_to_ristretto255
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "HashToGroup-" || contextString, and `expand_message` = `expand_message_xmd`
    using SHA-512.
  - HashToScalar(): Compute `uniform_bytes` using `expand_message` = `expand_message_xmd`,
    DST = "HashToScalar-" || contextString, and output length 64, interpret
    `uniform_bytes` as a 512-bit integer in little-endian order, and reduce the integer
    modulo `Order()`.
  - Serialization: Both group elements and scalars are encoded in Ne = Ns = 32
    bytes. For group elements, use the 'Encode' and 'Decode' functions from
    {{!RISTRETTO}}. For scalars, ensure they are fully reduced modulo `Order()`
    and in little-endian order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0001

### OPRF(decaf448, SHAKE-256)

- Group: decaf448 {{!RISTRETTO}}
  - HashToGroup(): Use hash_to_decaf448
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "HashToGroup-" || contextString, and `expand_message` = `expand_message_xof`
    using SHAKE-256.
  - HashToScalar(): Compute `uniform_bytes` using `expand_message` = `expand_message_xof`,
    DST = "HashToScalar-" || contextString, and output length 64, interpret
    `uniform_bytes` as a 512-bit integer in little-endian order, and reduce the integer
    modulo `Order()`.
  - Serialization: Both group elements and scalars are encoded in Ne = Ns = 56
    bytes. For group elements, use the 'Encode' and 'Decode' functions from
    {{!RISTRETTO}}. For scalars, ensure they are fully reduced modulo `Order()`
    and in little-endian order.
- Hash: SHAKE-256, and Nh = 64.
- ID: 0x0002

### OPRF(P-256, SHA-256)

- Group: P-256 (secp256r1) {{x9.62}}
  - HashToGroup(): Use hash_to_curve with suite P256_XMD:SHA-256_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} and DST =
    "HashToGroup-" || contextString.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using L = 48, `expand_message_xmd` with SHA-256,
    DST = "HashToScalar-" || contextString, and
    prime modulus equal to `Order()`.
  - Serialization: Elements are serialized as Ne = 33 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 32 byte strings by fully reducing the value modulo `Order()` and in big-endian
    order.
- Hash: SHA-256, and Nh = 32.
- ID: 0x0003

### OPRF(P-384, SHA-384)

- Group: P-384 (secp384r1) {{x9.62}}
  - HashToGroup(): Use hash_to_curve with suite P384_XMD:SHA-384_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} and DST =
    "HashToGroup-" || contextString.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using L = 72, `expand_message_xmd` with SHA-384,
    DST = "HashToScalar-" || contextString, and
    prime modulus equal to `Order()`.
  - Serialization: Elements are serialized as Ne = 49 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 48 byte strings by fully reducing the value modulo `Order()` and in big-endian
    order.
- Hash: SHA-384, and Nh = 48.
- ID: 0x0004

### OPRF(P-521, SHA-512)

- Group: P-521 (secp521r1) {{x9.62}}
  - HashToGroup(): Use hash_to_curve with suite P521_XMD:SHA-512_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} and DST =
    "HashToGroup-" || contextString.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using L = 98, `expand_message_xmd` with SHA-512,
    DST = "HashToScalar-" || contextString, and
    prime modulus equal to `Order()`.
  - Serialization: Elements are serialized as Ne = 67 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 66 byte strings by fully reducing the value modulo `Order()` and in big-endian
    order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0005

## Input Validation {#input-validation}

Since messages are serialized before transmission between client and server,
deserialization is followed by input validation to prevent malformed or
invalid inputs from being used in the protocol.
The DeserializeElement and DeserializeScalar functions instantiated for a
particular prime-order group corresponding to a ciphersuite MUST adhere
to the description in {{pog}}. This section describes how input validation
of elements and scalars is implemented for all prime-order groups included
in the above ciphersuite list.

### Element Validation

Recovering a group element from an arbitrary byte array must validate that
the element is a proper member of the group and is not the identity element,
and returns an error if either condition is not met.

For P-256, P-384, and P-521 ciphersuites, it is required to perform partial
public-key validation as defined in Section 5.6.2.3.4 of {{keyagreement}}.
This includes checking that the coordinates are in the correct range, that
the point is on the curve, and that the point is not the identity.
If these checks fail, validation returns an InputValidationError.

For ristretto255 and decaf448, elements are deserialized by invoking the Decode
function from {{RISTRETTO, Section 4.3.1}} and {{RISTRETTO, Section 5.3.1}}, respectively,
which returns false if the input is invalid. If this function returns false
or if the decoded element is the identity, validation returns an
InputValidationError.

### Scalar Validation

The DeserializeScalar function attempts to recover a scalar field element from an arbitrary
byte array. Like DeserializeElement, this function validates that the element
is a member of the scalar field and returns an error if this condition is not met.

For P-256, P-384, and P-521 ciphersuites, this function ensures that the input,
when treated as a big-endian integer, is a value between 0 and `Order() - 1`. For
ristretto255 and decaf448, this function ensures that the input, when treated as
a little-endian integer, is a value between 0 and `Order() - 1`.

## Future Ciphersuites

A critical requirement of implementing the prime-order group using
elliptic curves is a method to instantiate the function
`HashToGroup`, that maps inputs to group elements. In the elliptic
curve setting, this deterministically maps inputs x (as byte arrays) to
uniformly chosen points on the curve.

In the security proof of the construction Hash is modeled as a random
oracle. This implies that any instantiation of `HashToGroup` must be
pre-image and collision resistant. In {{ciphersuites}} we give
instantiations of this functionality based on the functions described in
{{!I-D.irtf-cfrg-hash-to-curve}}. Consequently, any OPRF implementation
must adhere to the implementation and security considerations discussed
in {{!I-D.irtf-cfrg-hash-to-curve}} when instantiating the function.

Additionally, future ciphersuites must take care when choosing the
security level of the group. See {{limits}} for additional details.

# Application Considerations {#apis}

This section describes considerations for applications, including external interface
recommendations, explicit error treatment, and public input representation for the
POPRF protocol variant.

## Input Limits

Application inputs, expressed as PrivateInput or PublicInput values, MUST be smaller
than 2^13 bytes in length. Applications that require longer inputs can use a cryptographic
hash function to map these longer inputs to a fixed-length input that fits within the
PublicInput or PrivateInput length bounds. Note that some cryptographic hash functions
have input length restrictions themselves, but these limits are often large enough to
not be a concern in practice. For example, SHA-256 has an input limit of 2^61 bytes.

## External Interface Recommendations

The protocol functions in {{online}} are specified in terms of prime-order group
Elements and Scalars. However, applications can treat these as internal functions,
and instead expose interfaces that operate in terms of wire format messages.

## Error Considerations {#errors}

Some OPRF variants specified in this document have fallible operations. For example, `Finalize`
and `Evaluate` can fail if any element received from the peer fails input validation.
The explicit errors generated throughout this specification, along with the
conditions that lead to each error, are as follows:

- `VerifyError`: Verifiable OPRF proof verification failed; {{voprf}} and {{poprf}}.
- `DeserializeError`: Group Element or Scalar deserialization failure; {{pog}} and {{online}}.
- `InputValidationError`: Validation of byte array inputs failed; {{input-validation}}.

There are other explicit errors generated in this specification, however they occur with
negligible probability in practice. We note them here for completeness.

- `InvalidInputError`: OPRF Blind input produces an invalid output element; {{oprf}} and {{poprf}}.
- `InverseError`: A tweaked private key is invalid (has no multiplicative inverse); {{pog}} and {{online}}.

In general, the errors in this document are meant as a guide to implementors.
They are not an exhaustive list of all the errors an implementation might emit.
For example, implementations might run out of memory and return a corresponding error.

## POPRF Public Input

Functionally, the VOPRF and POPRF variants differ in that the POPRF variant
admits public input, whereas the VOPRF variant does not. Public input allows
clients and servers to cryptographically bind additional data to the POPRF output.
A POPRF with fixed public input is functionally equivalent to a VOPRF. However, there
are differences in the underlying security assumptions made about each variant;
see {{cryptanalysis}} for more details.

This public input is known to both parties at the start of the protocol. It is RECOMMENDED
that this public input be constructed with some type of higher-level domain separation
to avoid cross protocol attacks or related issues. For example, protocols using
this construction might ensure that the public input uses a unique, prefix-free encoding.
See {{I-D.irtf-cfrg-hash-to-curve, Section 10.4}} for further discussion on
constructing domain separation values.

Implementations of the POPRF may choose to not let applications control `info` in
cases where this value is fixed or otherwise not useful to the application. In this
case, the resulting protocol is functionally equivalent to the VOPRF, which does not
admit public input.

# Security Considerations {#sec}

This section discusses the cryptographic security of our protocol, along
with some suggestions and trade-offs that arise from the implementation
of the OPRF variants in this document. Note that the syntax of the POPRF
variant is different from that of the OPRF and POPRF variants since it
admits an additional public input, but the same security considerations apply.

## Security Properties {#properties}

The security properties of an OPRF protocol with functionality y = F(k, x)
include those of a standard PRF. Specifically:

- Pseudorandomness: F is pseudorandom if the output y = F(k, x) on any
  input x is indistinguishable from uniformly sampling any element in
  F's range, for a random sampling of k.

In other words, consider an adversary that picks inputs x from the
domain of F and evaluates F on (k, x) (without knowledge of randomly
sampled k). Then the output distribution F(k, x) is indistinguishable
from the output distribution of a randomly chosen function with the same
domain and range.

A consequence of showing that a function is pseudorandom, is that it is
necessarily non-malleable (i.e. we cannot compute a new evaluation of F
from an existing evaluation). A genuinely random function will be
non-malleable with high probability, and so a pseudorandom function must
be non-malleable to maintain indistinguishability.

- Unconditional input secrecy: The server does not learn anything about
  the client input x, even with unbounded computation.

In other words, an attacker with infinite compute cannot recover any information
about the client's private input x from an invocation of the protocol.

Additionally, for the VOPRF and POPRF protocol variants, there is an additional
security property:

- Verifiable: The client must only complete execution of the protocol if
  it can successfully assert that the POPRF output it computes is
  correct. This is taken with respect to the POPRF key held by the
  server.

Any VOPRF or POPRF that satisfies the 'verifiable' security property is known
as 'verifiable'. In practice, the notion of verifiability requires that
the server commits to the key before the actual protocol execution takes
place. Then the client verifies that the server has used the key in the
protocol using this commitment. In the following, we may also refer to this
commitment as a public key.

Finally, the POPRF variant also has the following security property:

- Partial obliviousness: The server must learn nothing about the client's
  private input or the output of the function. In addition, the client must
  learn nothing about the server's private key. Both client and server learn
  the public input (info).

Essentially, partial obliviousness tells us that, even if the server learns
the client's private input x at some point in the future, then the server will
not be able to link any particular POPRF evaluation to x. This property is
also known as unlinkability {{DGSTV18}}.

## Security Assumptions {#cryptanalysis}

Below, we discuss the cryptographic security of each protocol variant
from {{protocol}}, relative to the necessary cryptographic assumptions
that need to be made.

### OPRF and VOPRF Assumptions

The OPRF and VOPRF protocol variants in this document are based on {{JKK14}}.
In fact, the VOPRF construction is identical to the {{JKK14}} construction, except
that this document supports batching so that multiple evaluations can happen
at once whilst only constructing one proof object. This is enabled using
an established batching technique.

The pseudorandomness and input secrecy (and verifiability) of the OPRF (and VOPRF) variants
is based on the assumption that the One-More Gap Computational Diffie Hellman (CDH) is computationally
difficult to solve in the corresponding prime-order group. The original paper {{JKK14}}
gives a security proof that the construction satisfies the security guarantees of a
VOPRF protocol {{properties}} under the One-More Gap CDH assumption in the universal
composability (UC) security framework.

### POPRF Assumptions

The POPRF construction in this document is based on the construction known
as 3HashSDHI given by {{TCRSTW21}}. The construction is identical to
3HashSDHI, except that this design can optionally perform multiple POPRF
evaluations in one go, whilst only constructing one NIZK proof object.
This is enabled using an established batching technique.

Pseudorandomness, input secrecy, verifiability, and partial obliviousness of the POPRF variant is
based on the assumption that the One-More Gap Strong Diffie-Hellman Inversion (SDHI)
assumption from {{TCRSTW21}} is computationally difficult to solve in the corresponding
prime-order group. {{TCRSTW21}} show that both the One-More Gap CDH assumption
and the One-More Gap SDHI assumption reduce to the q-DL (Discrete Log) assumption
in the algebraic group model, for some q number of `Evaluate` queries.
(The One-More Gap CDH assumption was the hardness assumption used to
evaluate the OPRF and VOPRF designs based on {{JKK14}}, which is a predecessor
to the POPRF variant in {{poprf}}.)

### Static Diffie Hellman Attack and Security Limits {#limits}

A side-effect of the OPRF protocol variants in this document is that they allow
instantiation of an oracle for constructing static DH samples; see {{BG04}} and {{Cheon06}}.
These attacks are meant to recover (bits of) the server private key.
Best-known attacks reduce the security of the prime-order group instantiation by log_2(Q)/2
bits, where Q is the number of `Evalute()` calls made by the attacker.

As a result of this class of attack, choosing prime-order groups with a 128-bit security
level instantiates an OPRF with a reduced security level of 128-(log\_2(Q)/2) bits of security.
Moreover, such attacks are only possible for those certain applications where the
adversary can query the OPRF directly. Applications can mitigate against this problem
in a variety of ways, e.g., by rate-limiting client queries to `Evaluate()` or by
rotating private keys. In applications where such an oracle is not made available
this security loss does not apply.

In most cases, it would require an informed and persistent attacker to
launch a highly expensive attack to reduce security to anything much
below 100 bits of security. Applications that admit the aforementioned
oracle functionality, and that cannot tolerate discrete logarithm security
of lower than 128 bits, are RECOMMENDED to choose groups that target a
higher security level, such as decaf448 (used by ciphersuite 0x0002),
P-384 (used by 0x0004), or P-521 (used by 0x0005).

## Domain Separation {#domain-separation}

Applications SHOULD construct input to the protocol to provide domain
separation. Any system which has multiple OPRF applications should
distinguish client inputs to ensure the OPRF results are separate.
Guidance for constructing info can be found in {{!I-D.irtf-cfrg-hash-to-curve, Section 3.1}}.

## Timing Leaks

To ensure no information is leaked during protocol execution, all
operations that use secret data MUST run in constant time. This includes
all prime-order group operations and proof-specific operations that
operate on secret data, including `GenerateProof()` and `Evaluate()`.

# Acknowledgements

This document resulted from the work of the Privacy Pass team
{{PrivacyPass}}. The authors would also like to acknowledge helpful
conversations with Hugo Krawczyk. Eli-Shaoul Khedouri provided
additional review and comments on key consistency. Daniel Bourdrez,
Tatiana Bradley, Sofia Celi, Frank Denis, Kevin Lewi, Christopher Patton,
and Bas Westerbaan also provided helpful input and contributions to the document.

--- back

# Test Vectors

This section includes test vectors for the protocol variants specified
in this document. For each ciphersuite specified in {{ciphersuites}},
there is a set of test vectors for the protocol when run the OPRF,
VOPRF, and POPRF modes. Each test vector lists the batch size for
the evaluation. Each test vector value is encoded as a hexadecimal
byte string. The label for each test vector value is described below.

- "Input": The private client input, an opaque byte string.
- "Info": The public info, an opaque byte string. Only present for POPRF vectors.
- "Blind": The blind value output by `Blind()`, a serialized `Scalar`
  of `Ns` bytes long.
- "BlindedElement": The blinded value output by `Blind()`, a serialized
  `Element` of `Ne` bytes long.
- "EvaluatedElement": The evaluated element output by `Evaluate()`,
  a serialized `Element` of `Ne` bytes long.
- "Proof": The serialized `Proof` output from `GenerateProof()` (only
  listed for verifiable mode test vectors), composed of two serialized
  `Scalar` values each of `Ns` bytes long. Only present for VOPRF and POPRF vectors.
- "ProofRandomScalar": The random scalar `r` computed in `GenerateProof()`
  (only listed for verifiable mode test vectors), a serialized `Scalar` of
  `Ns` bytes long. Only present for VOPRF and POPRF vectors.
- "Output": The OPRF output, a byte string of length `Nh` bytes.

Test vectors with batch size B > 1 have inputs separated by a comma
",". Applicable test vectors will have B different values for the
"Input", "Blind", "BlindedElement", "EvaluationElement", and
"Output" fields.

The server key material, `pkSm` and `skSm`, are listed under the mode for
each ciphersuite. Both `pkSm` and `skSm` are the serialized values of
`pkS` and `skS`, respectively, as used in the protocol. Each key pair
is derived from a seed `Seed` and info string `KeyInfo`, which are
listed as well, using the `DeriveKeyPair` function from {{offline}}.

## OPRF(ristretto255, SHA-512)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 8ce0798c296bdeb665d52312d81a596dbb4ef0d25adb10c7f2b58c72dd2e5
40a
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f
6706
BlindedElement = 3c81bf8dd3904b31919133cd383168a5d6a095995e233be6f7e
1e0f98c032b03
EvaluationElement = 36928eb62560fc007fbf78a7df0cb442d14f930432c3ad7d
2394a627cc8e691c
Output = 2765a7f9fa7e9d5440bbf1262dc1041277bed5f27fd27ee89662192a408
508bb8711559d5a5390560065b83b946ed7b433d0c1df09bd23871804ae78e4a4d21
5
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f
6706
BlindedElement = de95a2d749a05f36194e820a3ed84a4db814c2c26abdbb427c5
29a2e972c6006
EvaluationElement = bc7771a6fa5edec1613b3529d4127c3a9f64264c43d0ce2f
4e483eecbc33837b
Output = 3d6c9ec7dd6f51b987b46b79128d98323accd7c1561faa50d287c5285ec
da1e660f3ee2929aebd431a7a7d511767cbd1054735a6e19aee1b9423a1e6f479535
e
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 24d1aca670a768b99e888c19f9ee3252d17e32689507b2b9b803ae23b1997
f07
pkSm = 46919d396c12fbb7a02f4ce8f51a9941ddc1c4335682e1b03b0ca5b3524c6
619
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f
6706
BlindedElement = 80ce7827d93f7d1979550915b10766b3a82a1dfb65fe9c9a9b2
d227ad44cfc12
EvaluationElement = f42ba3e1085eda93942598da6511fa756e400dcfd8122ea3
b5fb8bf4f5ff012a
Proof = 7b12add3875a1c09668a9dbc14c27f9bc2a6339bc80c4173f1449bf262c0
080c2178b9c855e8064f3c0e123159fdbfdfec48bc77e6bcb6f5a64250fb050b690e
ProofRandomScalar = 222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d98
81aa6f61d645fc0e
Output = 453a358544b4e92bbc4625d08ffdde64c0dbc4f9b1501d548e3a6d8094b
a70a993c13a6e65a46880bbd65272ba54cf199577760815098e5e10cb951b1fc5b02
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f
6706
BlindedElement = b8268b2d81d74a21aa22b93eac47f5d97fa45de1d432aaa4c9a
9bcae888eb33d
EvaluationElement = d66cf7b6f99d9d3a177dd13b0dd3a9df74f2110107faba0c
2be5949bf6830164
Proof = e791ae4c2d0c7f7f82a129811c0f0e50514b2c8e3b33ace5da97a2def48a
5102a4ba0c7adabd94ddae562ba1c5fa536d935ab537506e9c7d38225e4d50234303
ProofRandomScalar = 222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d98
81aa6f61d645fc0e
Output = a2bacfc82a4cac041edab1e1c0d0dc63f46631fb4886f8c395f0b184a9b
7cbbef2eee05bbd3f085552d8c80e77711b2ad9ba2b7574e2531591380e717d29c6f
5
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f
6706,222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0
e
BlindedElement = 80ce7827d93f7d1979550915b10766b3a82a1dfb65fe9c9a9b2
d227ad44cfc12,fa542b5564bb61a7bd871cca3d1a5ae3be2a801ec90bd61fdbb8a5
a3a27f2f0b
EvaluationElement = f42ba3e1085eda93942598da6511fa756e400dcfd8122ea3
b5fb8bf4f5ff012a,96675c1732da587e80c3b6328bb99b3b89d8bcf071bf78d3ff0
dc366d69d1c1b
Proof = ce79f1aabbf3a41fdd75d8b0ba3b2faef1c6f590ba21c16b959597bcb4b0
ad067d73c78c14fed8d9d2c0527f5e13ece867d19793035f9f28b1e33bf26b934c07
ProofRandomScalar = 419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdb
cf037f9ea84bbe0c
Output = 453a358544b4e92bbc4625d08ffdde64c0dbc4f9b1501d548e3a6d8094b
a70a993c13a6e65a46880bbd65272ba54cf199577760815098e5e10cb951b1fc5b02
7,a2bacfc82a4cac041edab1e1c0d0dc63f46631fb4886f8c395f0b184a9b7cbbef2
eee05bbd3f085552d8c80e77711b2ad9ba2b7574e2531591380e717d29c6f5
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 02c1b949c3d65f83b18890aa8d099f6063fa6a72add8d776bc15a291fd08f
f04
pkSm = 1a2fac6b919790c613e0fbed070471778fbb1c6950d40a4e059acb652dc57
161
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f
6706
BlindedElement = f8dfe601a52f28346e793e014bd804466178bd96545450e6a07
a52b105afa728
EvaluationElement = b4424b4fad934c392012cc80a562b088532a49d20b515f66
d46e17a512c2e916
Proof = b26aaf80daf26ed1470e85337907b26d728f1f1d033c4a819edb705416d6
1906a933232a0fb5194e5cf912be9a6df52f462c84adecff24e68f1c2e59cdd5c004
ProofRandomScalar = 222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d98
81aa6f61d645fc0e
Output = 4d04eccb77a29bd8a00fb1e3f391e0601340c3dc874fc7bb16cfd92d961
532d18b4edfffaec94457cb19111bca1ecd19e46124c6a5d29703d09df5e5ab521b2
8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f
6706
BlindedElement = bc5877dd028c5538ee09281525c6e613d7215788de4fd58a253
ff0e882fd9962
EvaluationElement = c44c1c1ecfbdf85134cfac048b8cfc4a06fe3f0a83edd55a
9b2b6ef3b1f09f37
Proof = f9f604cabe68ce950a924bc1ba734e44111446c27ecb7c0fb4395bf4379b
160561b32f78cdb4f32b3d89916fe2fd4f2820b911f4c2cb352057950f6216f23500
ProofRandomScalar = 222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d98
81aa6f61d645fc0e
Output = a88ab2bceba2c9c5a0ee0ee45636e65042b5f274af864f8c1560d32ecee
4373c31907f237609d3f164beec32e3270588961c1d19cee467d2a3b0445ebdea215
9
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f
6706,222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0
e
BlindedElement = f8dfe601a52f28346e793e014bd804466178bd96545450e6a07
a52b105afa728,2016fcfe45a2df832c73ef2db415c24d394aa66b94f7c247569b0d
d88975a234
EvaluationElement = b4424b4fad934c392012cc80a562b088532a49d20b515f66
d46e17a512c2e916,1ee524b176295a62365b5cf4c94a60868155796300d3389fec0
56f5d76ad0122
Proof = b7cd91a95016ba5defb4da49a575bc824aaade15009261e03a115ab38448
3806ea3d789f79a16800b13b84494620f77620739f355ad40fb3e399cd4c3fe58206
ProofRandomScalar = 419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdb
cf037f9ea84bbe0c
Output = 4d04eccb77a29bd8a00fb1e3f391e0601340c3dc874fc7bb16cfd92d961
532d18b4edfffaec94457cb19111bca1ecd19e46124c6a5d29703d09df5e5ab521b2
8,a88ab2bceba2c9c5a0ee0ee45636e65042b5f274af864f8c1560d32ecee4373c31
907f237609d3f164beec32e3270588961c1d19cee467d2a3b0445ebdea2159
~~~

## OPRF(decaf448, SHAKE-256)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 416f3b0f4d13ac19e6aacade4ecf8b7e9c55d808311be2bea0dae4f4c56d0
73e7229b8b72a8c7eb68bd2e98336baaec1ac47c82cf2c5e33b
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa
3833a26e9388336361686ff1f83df55046504dfecad8549ba112
BlindedElement = 764cd0ea2c55ddb67934bfdcb4c017790c2a6d44ece7984d96f
7a263cb5f51e488266c8bf7b579f9d4d3f4f14c7286b94c4c9fa4ed3646b2
EvaluationElement = 0ac99dfc5e1f5d961edf15ed47f5323e8f0cb00708b6d5c9
7bc4ad243c4fef1692b2129832fd5ee92a0cb3863d1db3e435f85e1ef9c1ce5c
Output = b93d3ed18489c1236cc965d202254de35767ea673560d6c225cec0b30fe
3adc88fee63f8a78d127cd64c7077e1d3ac4a7cc761335c0bcdc12d6981ad8730285
8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa
3833a26e9388336361686ff1f83df55046504dfecad8549ba112
BlindedElement = 5c54b2323868e783f9a76abe20dd03d0cf7714aea7c71572f31
caaa75ca88843d7020708639e5e2239319ae5199b5c3178e79f5e3b79fedb
EvaluationElement = 58fb5dc2cc5edecd64720730643d50991f7e66d05edd2141
20b9f5d6511d291e5b0ad85ac1c01bbf1dea69c82ac7500a1333ec2fccfc451f
Output = aaf99e5a044bbce915bf3ba381e25da62e4b2cea4cee2f47f3662940284
579c0f8e1e011062ba010ca4f2c67a8157481c9ae7a458ea035a89e1948bfc5b8323
b
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 167e36766c08353fbc8fc46d89619f0306603a8ed33f7eafcca998ed2e890
d15f64a22b0196aaa298e4a502275d4ced5c6131de64597c500
pkSm = f27f3a898855240ef102d7bd6795aab2fa3972db3d47005cbd33e721cbed5
a3fd37508d093ecc645fa80a7f928c4313cfbd4654e8ea7de8f
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa
3833a26e9388336361686ff1f83df55046504dfecad8549ba112
BlindedElement = 906cdbb45449dae2d129198d522f1a577c85e439430b1132890
72aa51713b60dcd5d19864fa8a3ada1c2b4a321082efb4fb9174a1d155866
EvaluationElement = 9ed8d60ca1b39b9190d2458de9013a2f67507689aa169f9b
bbdbe163711d3ac07fc0a63b9b491e7fcdecaebb6facafc11d6030607b2a3f9e
Proof = 7d13478c13c56b83ce49062e94cac0f7387762dff274224a1a4cab39af8a
b806641b58324ff48dec0bf9e06c36b9ae63dc5416175750f025d877f00e3b524468
8ce4a6341f065f347a34c3f6d576056d8ca13099ca1afdf5c910c370cfbe35954be3
0c8c864a099eef0898b065eec306
ProofRandomScalar = b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0
627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b
Output = b558e37f6435a12fefded196936a4c1d0882bf4a115002920744ecb3128
43678f396f7d36711cf551750388ddf7a53a3aea7fd0ac60568cd2d4ead16a1ee106
f
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa
3833a26e9388336361686ff1f83df55046504dfecad8549ba112
BlindedElement = 2e0f10b6c86160cc3b3843c8194536b8b944f00ff354bacbcea
1e8aedcb785d10ff0a5c029479895a0e1f68b8d3b64f3755586950545e2c3
EvaluationElement = a217508ace196104ddec5efbe88c2ba57db40307baa516d9
ca855c00934045e634c348a99e7960ed2ec57fbce5d526af57d204637b4e77ed
Proof = 3a4718f5786659b0ba9c604dbfb89e604ced9f5bb807e72f2b84ec2d0722
4b72461c2ff026afb46bf3894d8c242cc645000189bba260de3f7841cecae0f16077
c573a858bd3b40c3dd4af5e2e08f802e33d5dc0ee1e826cfa7afcf19ac59a29bc741
e8a7e25192701d098ff07ca9c107
ProofRandomScalar = b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0
627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b
Output = eb14608be2f14c25b2c9fdd23690d293d0c6aaac501a3405b626b8699cf
34bb9dd4c2d7987b6391519b9480da453611509ba98098b3e79a35acd00f5e9d8abc
e
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa
3833a26e9388336361686ff1f83df55046504dfecad8549ba112,b1b748135d405ce
48c6973401d9455bb8ccd18b01d0295c0627f67661200dbf9569f73fbb3925daa043
a070e5f953d80bb464ea369e5522b
BlindedElement = 906cdbb45449dae2d129198d522f1a577c85e439430b1132890
72aa51713b60dcd5d19864fa8a3ada1c2b4a321082efb4fb9174a1d155866,0854a0
fb5efd2ae455f70a53d6b394c9629e4678ce47b5cc84e44e3b56cd2c4bc9977c60ae
8fdc20f110a373fe63b6770dbc5c1f5250bce0
EvaluationElement = 9ed8d60ca1b39b9190d2458de9013a2f67507689aa169f9b
bbdbe163711d3ac07fc0a63b9b491e7fcdecaebb6facafc11d6030607b2a3f9e,3a1
9cdb8b598eaf09ce3988a329e851914fecba1ebc593c1357e5ac8c93b1276c70d518
14b49c47f601bb78bf64955f269ba6ec1cba401fc
Proof = a6e77bd8aba8fdd8fd095f8038d7046363c58bd6d23d798a43658945baa1
5704b2d9637e86185e7fc1b245261c4476be617459dcbbb27b33a1c5ddb3cd296cd2
bd50fcc3721e3c8c83c716c83baccf95ef36b19babaa4b985487c0619b6130eb3aea
b5d86548129d3321fe5d8929ab29
ProofRandomScalar = 63798726803c9451ba405f00ef3acb633ddf0c420574a2ec
6cbf28f840800e355c9fbaac10699686de2724ed22e797a00f3bd93d105a7f23
Output = b558e37f6435a12fefded196936a4c1d0882bf4a115002920744ecb3128
43678f396f7d36711cf551750388ddf7a53a3aea7fd0ac60568cd2d4ead16a1ee106
f,eb14608be2f14c25b2c9fdd23690d293d0c6aaac501a3405b626b8699cf34bb9dd
4c2d7987b6391519b9480da453611509ba98098b3e79a35acd00f5e9d8abce
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = f68691e40ba92bfdf37acfff161f5404f9ae0e53c7cedb0a790ab17c4c0a7
4a314c24974057464185e2d2e648f74ee6663443646db2c111a
pkSm = 2a742a63231b139ce19eab43e7a855f32e5dcbd16ef52a7f968456a814104
5d49e3e28a995cfaa22ee104e22f2239f624b3fa7d41bf15186
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa
3833a26e9388336361686ff1f83df55046504dfecad8549ba112
BlindedElement = 52cf99c655d115765e53da1c645f83db1064e65c90f2cb138bc
97a91a8512864c0ec1e96f13a905d293713f51684eca991fa7e0a590f89f6
EvaluationElement = 3c0fe1cc318304ea31a32dc71e15a5380e18145f75aaa73b
f6624560094d52f81d7e986e23211e1c9b7c634ff2500a1b71eb7cc2d07ccc4d
Proof = 28a444ad57dc346620107f0f2dd00bc35c73d3e8185a4baf2e46b8b5df59
2ab430d9cda5434f31c07453df3e3ae24bb562655a32464f8b1bc203f2ca490dbf74
ea545d64d72f242b06e7544edcf1da208bcbde1d2369049270e0a3c5158b817f65b0
dd5784ac1f274f8009d709dc5211
ProofRandomScalar = b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0
627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b
Output = 1ffbf9591b674e6a089279a8319c75e949cc277d7b5c757361412180307
90755e90af009768e1b9240c9734d8886c6121123384140b26c38c7a6c4217a1b3d9
4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa
3833a26e9388336361686ff1f83df55046504dfecad8549ba112
BlindedElement = cc57c4a2c175ee40c0afa6e38b495bd06db5cc6733919923fa3
9a83018b3fa063a6f315e9f7780b1ecfee6c67d06e26be8aff1ddfbbcf6f0
EvaluationElement = c61ff92e3a23b8becf5b28ac7bc9ccc5891512bc1526322d
349691e0874b7554b0b91480901ceb0ee537f0ae9b136df47e286d15e4142422
Proof = df838095334008dae81f239e8a31735b4aec01b67ecbdb26fb416d613c9d
af7ccea7c73e6e6b819f3e64375df46c54ad0a32d5928d49a9231d51abc4f09bca72
67d0e9e6a4de3b95541b79e5036318ea763c04da57b113a577fc4549a50d63fcc3f7
ba70fed8d02e035d644d24d15630
ProofRandomScalar = b1b748135d405ce48c6973401d9455bb8ccd18b01d0295c0
627f67661200dbf9569f73fbb3925daa043a070e5f953d80bb464ea369e5522b
Output = daeb206a0e1fc120ebe4ad885f851f456f7d8908166839b7dc541f71251
4203d9a3589025b4bfad6a79c6d40bfbf217f44a9aa17874a1ec271b23cced72a44e
f
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec65fa
3833a26e9388336361686ff1f83df55046504dfecad8549ba112,b1b748135d405ce
48c6973401d9455bb8ccd18b01d0295c0627f67661200dbf9569f73fbb3925daa043
a070e5f953d80bb464ea369e5522b
BlindedElement = 52cf99c655d115765e53da1c645f83db1064e65c90f2cb138bc
97a91a8512864c0ec1e96f13a905d293713f51684eca991fa7e0a590f89f6,10850d
b652aa31fc066d8b86965135953da4bd4412221ba9514a887ff25256dd9c036bc764
d1218534b3371634eb2d5432a2522d17d6ee96
EvaluationElement = 3c0fe1cc318304ea31a32dc71e15a5380e18145f75aaa73b
f6624560094d52f81d7e986e23211e1c9b7c634ff2500a1b71eb7cc2d07ccc4d,2e6
e249acd17fa21e5f8826630176dfde84acca27260629954e2c4aac25a090e77b99d5
7b0cc83acad33c64fb816907e64d8202b41784991
Proof = 1410ce9d6723ba41a678f756d2d82667b5bcf340fab036070fa5f95c5f2c
b643aad325405bfe6a90772a700c368dda7d375dce072fce6b2bc75e95cd5deaf417
f0e6a54ff4b4e6b8c96941f10f71beb40badfa6a338fdb9d93238e4baecd509d6479
827747704f14b832f7f5ff8e2619
ProofRandomScalar = 63798726803c9451ba405f00ef3acb633ddf0c420574a2ec
6cbf28f840800e355c9fbaac10699686de2724ed22e797a00f3bd93d105a7f23
Output = 1ffbf9591b674e6a089279a8319c75e949cc277d7b5c757361412180307
90755e90af009768e1b9240c9734d8886c6121123384140b26c38c7a6c4217a1b3d9
4,daeb206a0e1fc120ebe4ad885f851f456f7d8908166839b7dc541f712514203d9a
3589025b4bfad6a79c6d40bfbf217f44a9aa17874a1ec271b23cced72a44ef
~~~

## OPRF(P-256, SHA-256)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 88a91851d93ab3e4f2636babc60d6ce9d1aee2b86dece13fa8590d955a08d
987
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 035bb0ba00674ebe719b8325de25403a735c9a26c2935baaece
b5ee1afc27e0a74
EvaluationElement = 0364f2f4378a0ac77fd3cd24208e3d933ca706454487f7ed
c97c9e95add4087249
Output = 413c5d45657ce515914232ef0bafdbc1bfa5c272d4b403f2cea0ccf7ca1
8f9be
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 02d08d71085cf7e5289a048c0e482d9aec87d8d857177322474
5c6f1d47c6dacca
EvaluationElement = 03722a868fc6238e1753283cbe537b2c0f90930315700954
cdeb5fd98d98292e92
Output = 2a44e98a9df03b79dc27c178d96cfa69ba995159fe6a7b6013c7205f9ba
57038
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = c8a626b52be02b06e9cdb1a05490392938642a30b1451b0cd1be1d3612b33
6b5
pkSm = 0201d3da874a209120ac442081e9ef9ed8ee76fda919d0f386cb5a0143755
b10df
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 023c53221cdf25cfa39f9d1679dcebe775f926a747876f9586a
ea6a5770996b53a
EvaluationElement = 03a60753c7cc763abecd2d77532da0d46de3ce9a0d54141d
5810d77bdc3d88d782
Proof = b604637af60f200e8b9ae0b2721edf44a3781478a52547677811df75c31b
b22ed77292210123d99cf0da57af5d3f6d4b00627bde921326250613a5a928bf0a8c
ProofRandomScalar = f9db001266677f62c095021db018cd8cbb55941d4073698c
e45c405d1348b7b1
Output = a906579bce2c9123e5a105d4bdbcafb513d7d764e4f0937bee95b362527
78424
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 02e017029c441d3866cc661c29e6c337eab7d02e9bf0d002cac
a6d791a328584cb
EvaluationElement = 0397c2c677ac00564dd69f347dc1d94b5a3a10ae6661371d
61f5a01fdc0ee8bda2
Proof = 743597331547723a3f6e7777c8958d32b2c889a3b7f72239e36518236225
2b51058f7a293a168a7082391c19bcab7d783d2265e62c850cc2ca6501d7af9e82ea
ProofRandomScalar = f9db001266677f62c095021db018cd8cbb55941d4073698c
e45c405d1348b7b1
Output = d13c62d285a71acb534dcebdf312bfec0e2a3fcb79f4ac32d2dfb0bc9aa
e3cc7
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364,f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b
1
BlindedElement = 023c53221cdf25cfa39f9d1679dcebe775f926a747876f9586a
ea6a5770996b53a,028e875453293ed00e2f7995033f288b65f0d9770b4a7deee2fc
e7fc2764118288
EvaluationElement = 03a60753c7cc763abecd2d77532da0d46de3ce9a0d54141d
5810d77bdc3d88d782,02f1516f981aef6d053cd81c7fe0393ae367f1c21bc2a9cc0
2d8e484e5809cafa3
Proof = ef4afc47c7950fd50b49dac7b28c17a48637df405c36b29f9e7a1bbdee3f
e8d57f70140ae61545e084c1ab9baab01127e0543405f249dd11dc310ae7c4499f19
ProofRandomScalar = 350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba
51943c8026877963
Output = a906579bce2c9123e5a105d4bdbcafb513d7d764e4f0937bee95b362527
78424,d13c62d285a71acb534dcebdf312bfec0e2a3fcb79f4ac32d2dfb0bc9aae3c
c7
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = b75567bfc40aaaf7735c35c6ad5d55a725c9d42ac66df2e1dbd2027bde289
264
pkSm = 02eca084e8d6ac9ed1c5962e004e95e7c68a81e04be93ceabf79c619de2bc
c3eb9
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 03c6644da873e205615de14999fe81d4f8505efd33021e46279
1022dfec4eb192f
EvaluationElement = 0268206d26de670ca926ca6488d5dc9f2c78732d156f2449
26a3e7f631b06bf913
Proof = 9147c09d9111b1dec75c691e38b0b16039e4d5dbc261d6dc823741957efc
dd5ce620dddd7f686e963f5a8ce87a33c33a0b844e74be1956e6d14b4af9eddc483c
ProofRandomScalar = f9db001266677f62c095021db018cd8cbb55941d4073698c
e45c405d1348b7b1
Output = 15fce9922a2307349aac2eccc41941283e3c5e938aaf2506f99a6d8b6ee
34ef8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 0258bac052ceaff4a3d16cd7df9a7d0549afa33d15606e212fa
cbd2659fd66b514
EvaluationElement = 027b3582d4a4983623af8ba183ead192ee08964fc3285eb0
b6917b497824c565be
Proof = e7edde13b9fad5f01a39bb30c127a6ff374e5ea7fe154811e3590b3bea66
c8abcfee6c9b9ff401bd6948c73428bef3baa74885fe5c1dac16b9bcb3299330d385
ProofRandomScalar = f9db001266677f62c095021db018cd8cbb55941d4073698c
e45c405d1348b7b1
Output = a06ed7380210856caaba173bcad06266186c6638d86e372c3c96b9bd2f3
53543
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364,f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b
1
BlindedElement = 03c6644da873e205615de14999fe81d4f8505efd33021e46279
1022dfec4eb192f,02f5ca70e337297b8f6615bb45c548adec84c4b83eb9e8a90079
8f6d663ef65ae9
EvaluationElement = 0268206d26de670ca926ca6488d5dc9f2c78732d156f2449
26a3e7f631b06bf913,030afda278d58f3a307bdf556021c25c02c29feb7f0d04b91
e56a1297cb6ed531b
Proof = a69a104350ee01ca2cb5145e9256b83bc4297af728d2f2d55d85d45a9b1d
137f677ad7392c36728ebae5e92febac12444de6f5680550367eebbc8549607d96a0
ProofRandomScalar = 350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba
51943c8026877963
Output = 15fce9922a2307349aac2eccc41941283e3c5e938aaf2506f99a6d8b6ee
34ef8,a06ed7380210856caaba173bcad06266186c6638d86e372c3c96b9bd2f3535
43
~~~

## OPRF(P-384, SHA-384)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 8b0972b97a0339dbcdb993113426ce1fe1b11efefe53e010bc0ea279dda2e
37ac7a5599acec1a77f43a3ac7a8252782f
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562
889d89dbfa691d1cde91517fa222ed7ad364
BlindedElement = 0353059f07b8a7f684d92609820ba705bff7ce6a96381a91c84
9572c73b2a19d26f3a57cf53158bdc04dc3f014d33a04ac
EvaluationElement = 03687305e0b3716a3dfd976d4abdf7d313b2d02bbbab6f62
1bdfd82e489c64f9e138dc551ef758fc8356450d03ca623d02
Output = b2e380ca96ea80f7550a6b663e5f7752d7d7772c46169d72308a8425903
1e804ba577ac34e632f535a9519a692734016
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562
889d89dbfa691d1cde91517fa222ed7ad364
BlindedElement = 03ff1723eb5b5d33056738ddc556ae33dafddee6e7e82f3db17
d06d84b851da1e649d0bf37789391eb331a51991b82eff5
EvaluationElement = 027c13fc55a9e1d0543babd242e576fee49e0edd691f743f
51daf667cfff594976be32843c9c8f6e37bdd5cb3f3caa61a9
Output = 1d155a7ba2ea75c4f1e76fb0a37231e9b0776eed3f24a6541a01907ca8a
fb984a74408e6d2de8e481cae5dd03bdae3ce
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 70855cb96c961b39ea3ea5776d89c8b7623f5891a26e8437f86e2c713bdb0
da23415590a28184dc22088a215ebc7fe45
pkSm = 02d7bdae4b97ecf0fbb8c00cff3a3a9b6d0fb0cc34f8490a98a74dbb59a85
f43bda8ca7b3c0b05164f38d8efdef2c3426a
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562
889d89dbfa691d1cde91517fa222ed7ad364
BlindedElement = 0390bef097d3564253db83576cb359d396558405ef47ce40fe4
12e56c415d76f1188e9ddaff0cd8ca49b915eacb1898f82
EvaluationElement = 0201cbd445919eb58b6e889b8102999370017b2a03ab8693
53e13d60169fd571d7328eda5bb12b741a1079ec164034474e
Proof = 69dc1da7ae01c69dc2b1dc0ee867928ec966b837ba07b3e91bd69fb55472
8aeb5821fab217eae285b29aaaa4665c579972acf7d2c6e6a8b0f50edf804995c15c
1c413d5861d5d344521ddf539e503a1b8894acf1bd9d2f43753bf39625cf8c15
ProofRandomScalar = 803d955f0e073a04aa5d92b3fb739f56f9db001266677f62
c095021db018cd8cbb55941d4073698ce45c405d1348b7b1
Output = f18884ace2e342f849cea7f2f17de902b9884574fdaa8f507356f482c6b
67013f329e8c899b3c2c154af1defaa11d656
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562
889d89dbfa691d1cde91517fa222ed7ad364
BlindedElement = 02965013c1f69a494bbfb4a9b4d3b4dcffcb8c4d7218abc1072
1d4e7385e7c6996b1b8efdf77e5b5b69eba1c99a3f0232f
EvaluationElement = 03231d4ac74a7aa86ec18271256dc091aaaf4637c93aa5fb
d19c60540befc439bb201c524c710dae67bedaeab21793804e
Proof = 83d7cf2da3733f378aed2ff5b98d9b6bdcd99892ae20905e04ee1ddd280a
8ef8f1fdd56f070f67134db3ae4089372cea042f2eb769d00128bf22bd1996a99083
0e7e4a5300ced7ff2c6c097b2a1f1b0cc3c195527678d4d48f46b415e84626d9
ProofRandomScalar = 803d955f0e073a04aa5d92b3fb739f56f9db001266677f62
c095021db018cd8cbb55941d4073698ce45c405d1348b7b1
Output = f91d172cdecdea4f8299c8b39426db4c47428b82f8872b8539ad9b019de
b48b8d3c928c572ed988d5591a4442c060438
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562
889d89dbfa691d1cde91517fa222ed7ad364,803d955f0e073a04aa5d92b3fb739f5
6f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1
BlindedElement = 0390bef097d3564253db83576cb359d396558405ef47ce40fe4
12e56c415d76f1188e9ddaff0cd8ca49b915eacb1898f82,02c4d94d82346297e29a
b7fc1ef80775816bb6f053e00ff1763d3dbc84d233a89ec07a05d461108086d68a71
e32cf99fd5
EvaluationElement = 0201cbd445919eb58b6e889b8102999370017b2a03ab8693
53e13d60169fd571d7328eda5bb12b741a1079ec164034474e,02eb781c077132c12
69f1965853df02a67fc0caf6471b06071ce56b5bbefdb2bb1cdbe238a93ebf1f957d
3ac1b375be834
Proof = 977659cfc5d53b979ae8cbcaf293af53dbd4e9d36d702677d4cbfb337cd6
8e5bc8afab2f64428cdf3af2a19ce5e719621ed316df9b79bcc41d4d8dd40f71678e
33064a08462c72db9b825139673d031089fda00498112563d4f4b2983afb9634
ProofRandomScalar = a097e722ed2427de86966910acba9f5c350e8040f828bf6c
eca27405420cdf3d63cb3aef005f40ba51943c8026877963
Output = f18884ace2e342f849cea7f2f17de902b9884574fdaa8f507356f482c6b
67013f329e8c899b3c2c154af1defaa11d656,f91d172cdecdea4f8299c8b39426db
4c47428b82f8872b8539ad9b019deb48b8d3c928c572ed988d5591a4442c060438
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 2b65a799c107905abcc4f94bdc4756e8641112ae1fc21708cd9d62a952629
38ded6834e46bad252b4e533ee7eec7e26e
pkSm = 0286f37b6295bba7ebf35d2bfbb944d441fc416e51eb5ceeb63ac98afa6a6
27ccafe20bd600c728bc5b1300148ef2ba6e6
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562
889d89dbfa691d1cde91517fa222ed7ad364
BlindedElement = 032a8f6b124d8e1250962520bc4f75e602450d24aa94b5a98f6
5e45833fd172b1179f5744ef1309c712cb8445114b2101b
EvaluationElement = 02741204196ab532be6da3d38cd40e694848de52dd7701fb
a13d586a7b94e0c223804e33ba81cdf8d0cc07d6716d2efa57
Proof = 316027ffae977e73bb3abbdec98a28e284212b36505fe9a077b17d6c20e4
18631e8d26bb88c8d3d7d89bb45b8160907f569b0af0cf61a1ad44ad147a84832a5d
c12b35ea570220ea98c73487ae168915bc567be135330707931e1bece088625b
ProofRandomScalar = 803d955f0e073a04aa5d92b3fb739f56f9db001266677f62
c095021db018cd8cbb55941d4073698ce45c405d1348b7b1
Output = af52cf184180177970be0770e1c7920aa307b767556a13de38a64723d8d
cc7b344af9b6dd8f117ac2cef249ee3acc8fb
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562
889d89dbfa691d1cde91517fa222ed7ad364
BlindedElement = 03575ebea600fab9320792c3d7f00bd745379af7ed74e88e32e
6f905f87f3cf6fdd33360f781d2458100950685d27afb46
EvaluationElement = 03fa14912d784d3b62b546dcee4747441b04831bc9f4a3ee
5979492bb21fa1c534cbe4a360bf66e4be250c6443dc409d58
Proof = abdd6ab72b2a5a0481fdf3ec08757883a0751e3e4a02a77f06b07199c36f
1562ee7a4a512a9e3af6da97671d5d52fe459b4261ac7b2f1edc5a1d9b26bd6c486c
c790d13cbcf7ef4f7b20f425781c6159e4e86a5024bb7942d2ddbcf2adaa2dbc
ProofRandomScalar = 803d955f0e073a04aa5d92b3fb739f56f9db001266677f62
c095021db018cd8cbb55941d4073698ce45c405d1348b7b1
Output = 8bc546462de3087cddafcf81435d5802c0c31f557c791b115a092d5b71e
a2b6e20986bb624ead85c7a63c976c05dcddd
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562
889d89dbfa691d1cde91517fa222ed7ad364,803d955f0e073a04aa5d92b3fb739f5
6f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1
BlindedElement = 032a8f6b124d8e1250962520bc4f75e602450d24aa94b5a98f6
5e45833fd172b1179f5744ef1309c712cb8445114b2101b,03ab250abf2f80873239
3d36c19fb074539d5bee1d49282fc24fd65cc92fb89e1344e39efa9b5383b5405f09
5ab24c8faf
EvaluationElement = 02741204196ab532be6da3d38cd40e694848de52dd7701fb
a13d586a7b94e0c223804e33ba81cdf8d0cc07d6716d2efa57,039a16e5cf4bd6286
e4e0a289ac2d6b7706497eaf3a9b92bb7885a21cde4c6035f52a4f6fbb20d20defc3
b4561070734bd
Proof = ad28ac4c339bd22be4a1c00044046ee0cc2ba861abe0a5bdefd816bfbbd5
d48312c5aed62e38b3a47e61ac12aa8445e8a57d496bc5c7653bd1b95cd870626b9f
74632854fc3cd2d007fc19ae5410e3019228cc0ab37ed92ed3fbc9e23e75bb71
ProofRandomScalar = a097e722ed2427de86966910acba9f5c350e8040f828bf6c
eca27405420cdf3d63cb3aef005f40ba51943c8026877963
Output = af52cf184180177970be0770e1c7920aa307b767556a13de38a64723d8d
cc7b344af9b6dd8f117ac2cef249ee3acc8fb,8bc546462de3087cddafcf81435d58
02c0c31f557c791b115a092d5b71ea2b6e20986bb624ead85c7a63c976c05dcddd
~~~

## OPRF(P-521, SHA-512)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 00dc7a8db919a1076810a0c1503716d91668fa9edc60952317f26d47a090b
70dcfd3f530d07f48675cf8236d1daa81f3ff0f289942632e5cefd27a2190f0cefdc
302
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f68616333
88936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 02011aced348b845f99b0c85449d2be9a300618a8506adcc129
ccef314e535b3f3c3f2abde3795122b096d87fb386231ed4fa984c3683bb2e18ac45
a2c132f926099c9
EvaluationElement = 02006a8b93008044f8c66bd7c0dd567fec9a762def86bd05
ead79c372a94a67ee9aaf850525e88f22f6a37c8339dae0c21ceeda1267e60faf6f0
410c533adb24e5a6ad
Output = 383e3098d74b43f75d2e1136d7e7c08702d992e6f5f24f2bd438f98b86d
9d143ce87281b2daf7d67c94370903ba81495655d6e9626443a895b37bb74c0276f2
a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f68616333
88936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 0301f58980ba294825a67b6927bb428d356389f4e2c0b2faf7b
f6c3cf7a2fdea5bab1e94a9117d9727c224369787912e87afe86f4d3ff77b7502b64
a4575be5ad83c53
EvaluationElement = 0301e9186f6520a8ba78c84cd2d9c58c4c1991489bbb7fdc
179c987590ba1380afb7994b9180dab6ce676a64296b1b09853114eb2b28f3fd174a
80a90188592646ce87
Output = 5100f12a88477ba993cfe8eb5a82a835892b7fa3bdb47dc1db19725e4c1
138798e0f965df4f649e3a159aaca1fdd07034f7b91c0c9ac3d064b50953bb5c867c
3
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 00ef23ce13076b43a5a33e8fb8f94c940bbeabb762e5380d69cc9fa82c22a
8de39431c99e8b9d9fb75ea90446f895db04fe402b8be2c9df839f7d10ea6a23e7e0
eb4
pkSm = 020006090cc9a6f2eaef7e12759a8b5362e9972b4f36c4b3a3d71c4b67469
638593ed8f46291542e0f04fd462a8e8ab96047be087a9d3fb182f4c138c6fc95659
3b205
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f68616333
88936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 030181905551428f9079bbb4e0d9edae69e8d59ef39c1c6c3fb
7375e3b671c0b1b8615da03fd12416031230bf94f071e4c7f51bd6fbfed661f417bd
ff048901ff66ea3
EvaluationElement = 0201051c683721ec927785273a26cdf49c9a40b270217074
cedc7587b30d9ced98345058066a4797706d9f2ee54c6daa0002bb281b8280f9be42
09c063d4fcea9cccb0
Proof = 01436def6591ea99e6fc639d633e9cd2884b61d19cb5c047075d46ad1ee7
f9cbc87c05366b77fc4d9c2f44a25ff302e8a1b2c5d18886f4c5bc622686c6b12e2a
a23301fa11e16ac9954758852d90733ef77b123387455c379b791bab9547bd69be75
31cce3395bcb31cde638014586e346e34272090ab077b18452704faaedeeea0bb429
ProofRandomScalar = 015e80ae32363b32cb76ad4b95a5a34e46bb803d955f0e07
3a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698c
e45c405d1348b7b1
Output = b3e837431aaafdfa8efbf486d70ca2d4364ef86afc7a8941d9bf1a6adb7
bfd8c5302f91ee5796d956b5d3ea95fd0138d55d3059b1f4febf8cfd552e31fa2cf9
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f68616333
88936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 020154d9aef86ab04cbf3863c93cbdf660f9561ce1d1ad16dc4
b0cc10704f713e8bb57a0f854c9997956fec5fa0203956d170316bdd763cd2a144b2
b093ee0e7d4c091
EvaluationElement = 0201e5a75eeaadc88c2efec7e5c2bf13acd8842eb247db80
59b35cb5264c96618b663703887871002cf60b0e338b3dda841d33b5d47f47a910a1
52bf4ac99a470cbdb8
Proof = 0196d1c7e0f402f67a85468397e70574b5e94b3b3afb8b99f6ccdfc7f35a
03383d1ec8dace9509687cd97e3a5854445ccb476e511b34e8f3a3614c5540286f9a
7c6b000f8cc2b0703d01686254fe79e992fa5e2624d8c602ea9361e5e128eb7d001f
fab816096c96dcc1ea0ccdad759b82ea312194f75ca73fc2652b552e755afe2a7c6d
ProofRandomScalar = 015e80ae32363b32cb76ad4b95a5a34e46bb803d955f0e07
3a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698c
e45c405d1348b7b1
Output = e8f92bac6c7ae89918d724697d8c45da339f55b61d527c50104e6658280
3a8e6dcceae31b0d499e471aca460194a011d6b8b94fe2886b8b5a0c242079bfbf09
c
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f68616333
88936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364,015e80ae32363b32cb76ad4b95a5a34e46bb803d955f0e073a04aa5d92b3fb7
39f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b
1
BlindedElement = 030181905551428f9079bbb4e0d9edae69e8d59ef39c1c6c3fb
7375e3b671c0b1b8615da03fd12416031230bf94f071e4c7f51bd6fbfed661f417bd
ff048901ff66ea3,03018b719ebabfd1882cc5ccad8952d6ce0c4a32125498f18df8
d23c5f2dcd90877ad7e5d803d2eb20e11512a62f5bf7a39faff02af2eb74bb54f9b1
a0660598a7c1a3
EvaluationElement = 0201051c683721ec927785273a26cdf49c9a40b270217074
cedc7587b30d9ced98345058066a4797706d9f2ee54c6daa0002bb281b8280f9be42
09c063d4fcea9cccb0,020112158d9b8209cbb45f2d468bcc468bc91c4a2dd792d79
a13ebaf8a3e9a756fe8c112546c59a01b989e19fecad557f2228949724005aaca0d7
4df4ff1c3c9630fa8
Proof = 01070dcad57db044721fb947680fe3d5d48cee6597ffd6ae0a0a3dbe5b40
8e1f6e838118f466ad4f14a286dc3dcdd0ac446b0470fa74850e4cd5013ff967cf16
71ec0041ce44235c136b89165f9e17124f0f0c4550c3224c99fcdd04cc3a3ac2d61e
f69f07af7e67b7711e3baab4c723ab4bcc61a0efa206639fed728dd3296b2eaaa878
ProofRandomScalar = 01ec21c7bb69b0734cb48dfd68433dd93b0fa097e722ed24
27de86966910acba9f5c350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba
51943c8026877963
Output = b3e837431aaafdfa8efbf486d70ca2d4364ef86afc7a8941d9bf1a6adb7
bfd8c5302f91ee5796d956b5d3ea95fd0138d55d3059b1f4febf8cfd552e31fa2cf9
7,e8f92bac6c7ae89918d724697d8c45da339f55b61d527c50104e66582803a8e6dc
ceae31b0d499e471aca460194a011d6b8b94fe2886b8b5a0c242079bfbf09c
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 01f8c6fb8fb3265b70e97870f942f7de645132f694c139446ab758871bdf0
058a2a83b4679fc9fc1c6a0936b2f2e8e079a75b20688d4fe828e74d16bfc6255289
92e
pkSm = 03013db33ba3e475e5696be39d99fd9ffd96452c4fe78df4eef5723097943
1f734aceefad464c4885b99313a775f5f4524db3c8404400169fd139ca053b75c6d7
e848e
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f68616333
88936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 0201b63743d47fcbe3f29ec9137d63a805911eebdafc9dcb73a
2fc7d0db46d6c422556aa4d83cb99cd6363e84fd5a5582d0440ebbf7cf5280e233a4
8b080b661f41bcb
EvaluationElement = 0301a57148b1858dadfe5f901c72b77f4db6e62a5610d9bf
e4f5ffe3d2dcb23b27f7d3d9ad0d84374d24f8ff40875ce0cf79d44a79567caa4839
a2d8b28b5ec98962b2
Proof = 01d87491b3d5607adce3dbbc482697f173eeff14f445d406d0b977a25bc4
1dbac554846e5ef3d6d4eb94ceb1de93a98e06f49ae1f94efa4fe548e01758bb5141
6d7501c2d596eed6dfb40d296ae165eb4b93b6adf92248bba5e0e1884973da4738c7
2eb62f38982a6ae9c99a4359ac0d6b28c1cbcf19e8d44b530b02264e6fe720126f26
ProofRandomScalar = 015e80ae32363b32cb76ad4b95a5a34e46bb803d955f0e07
3a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698c
e45c405d1348b7b1
Output = 70ad5e29de9f6e35f16afab3b97c1b26fdf6be0da60aff48a99980ddb8d
7c2d728a8a5d2837179bfddd612712e014c0c9b9596cbb5a6ee6761c564dbb8921b4
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f68616333
88936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364
BlindedElement = 030120f05e8051b34a54be62ff9809856c47951aa6c9a8d2d9c
af5e65bdb9c982086ab4d8319dcc4a031b2b6bc3f5c52cbcaed4007acec06d4e81d5
f4815bb126b9912
EvaluationElement = 0300e10c99d6d35975940ee330b9dc2183779dd18fe10328
39256503d0edee34f22edb8ad37b44af9502c842b7e981b0eaa391700f1097d4a069
9ef7f544a8d765a9f9
Proof = 01c76999a64c9ce8595e198c413bcc1968cbb8ce37fa7b696a02003294c6
bb60d839e75f1e7bf6de4d399f9f38093396bba7113fbbdcaa37e73ee45849557dc6
ed2e00422c693ecd1b89cb807063742570d54effb31de0dd9a4989c6e8d096520b47
20c271640bb5ebcf32e9c5127ed955b1b46e58772ebd61e8ea9426104f428d35a192
ProofRandomScalar = 015e80ae32363b32cb76ad4b95a5a34e46bb803d955f0e07
3a04aa5d92b3fb739f56f9db001266677f62c095021db018cd8cbb55941d4073698c
e45c405d1348b7b1
Output = ee2d8e42030da6283ab59a11f41a171c65e208306e00c6f965a56c10f33
bf0942bb38b7e1a33c70bc3542d27220379cbcef8b91898c720be948e9db214a14bb
9
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 00d1dccf7a51bafaf75d4a866d53d8cafe4d504650f53df8f16f68616333
88936ea23338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7a
d364,015e80ae32363b32cb76ad4b95a5a34e46bb803d955f0e073a04aa5d92b3fb7
39f56f9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b
1
BlindedElement = 0201b63743d47fcbe3f29ec9137d63a805911eebdafc9dcb73a
2fc7d0db46d6c422556aa4d83cb99cd6363e84fd5a5582d0440ebbf7cf5280e233a4
8b080b661f41bcb,0201f8fcd2e0b4e75051bbd78ad3468a06e56ca75c5dfb4cf9e8
6b75b4ad231d53702e87e2acba766dc2c8bf7227d9e88cf063cde2570e23108c022e
673fbf20ff17a9
EvaluationElement = 0301a57148b1858dadfe5f901c72b77f4db6e62a5610d9bf
e4f5ffe3d2dcb23b27f7d3d9ad0d84374d24f8ff40875ce0cf79d44a79567caa4839
a2d8b28b5ec98962b2,02001bb74394c3e749e20d22fead8f2ba637cc373a6109a3b
18b36efdb327298df8e18eabd6a127566aa9aa90fbfa7b62edf20e6001f537e109f1
72ddec25c9f9ba3f3
Proof = 01b4a3ac7b59d03938dc76e9d1a051b24deafecc3660ad1021c3aa728935
fb2deea754d444d41f40f1b283be6e4e3161f285ec407d34b9aa4f78178830ba8d9c
8dee00105266b7c07151acbb871a7b60919f68e624b3f793bca516bbd70dce447c7a
83f584e9ba63c204ffa09406c5421d287ddfaedd067b903c1e0a07df2fca170bb82d
ProofRandomScalar = 01ec21c7bb69b0734cb48dfd68433dd93b0fa097e722ed24
27de86966910acba9f5c350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba
51943c8026877963
Output = 70ad5e29de9f6e35f16afab3b97c1b26fdf6be0da60aff48a99980ddb8d
7c2d728a8a5d2837179bfddd612712e014c0c9b9596cbb5a6ee6761c564dbb8921b4
e,ee2d8e42030da6283ab59a11f41a171c65e208306e00c6f965a56c10f33bf0942b
b38b7e1a33c70bc3542d27220379cbcef8b91898c720be948e9db214a14bb9
~~~
