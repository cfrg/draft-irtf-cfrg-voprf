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
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: armfazh@cloudflare.com
 -
    ins: N. Sullivan
    name: Nick Sullivan
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: nick@cloudflare.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    street: 101 Townsend St
    city: San Francisco
    country: United States of America
    email: caw@heapingbits.net

normative:
  RFC2119:
  RFC7748:
  RFC8446:
  PrivacyPass:
    title: Privacy Pass
    target: https://github.com/privacypass/challenge-bypass-server
    date: false
  BB04:
    title: Short Signatures Without Random Oracles
    target: http://ai.stanford.edu/~xb/eurocrypt04a/bbsigs.pdf
    date: false
    authors:
      -
        ins: D. Boneh
        org: Stanford University, CA, USA
      -
        ins: X. Boyen
        org: Voltage Security, Palo Alto, CA, USA
  BG04:
    title: The Static Diffie-Hellman Problem
    target: https://eprint.iacr.org/2004/306
    date: false
    authors:
      -
        ins: D. Brown
        org: Certicom Research
      -
        ins: R. Gallant
        org: Certicom Research
  Cheon06:
    title: Security Analysis of the Strong Diffie-Hellman Problem
    target: https://www.iacr.org/archive/eurocrypt2006/40040001/40040001.pdf
    date: false
    authors:
      -
        ins: J. H. Cheon
        org: Seoul National University, Republic of Korea
  JKKX16:
    title: Highly-Efficient and Composable Password-Protected Secret Sharing (Or, How to Protect Your Bitcoin Wallet Online)
    target: https://eprint.iacr.org/2016/144
    date: false
    authors:
      -
        ins: S. Jarecki
        org: UC Irvine, CA, USA
      -
        ins: A. Kiayias
        org: University of Athens, Greece
      -
        ins: H. Krawczyk
        org: IBM Research, NY, USA
      -
        ins: Jiayu Xu
        org: UC Irvine, CA, USA
  JKK14:
    title:  Round-Optimal Password-Protected Secret Sharing and T-PAKE in the Password-Only model
    target: https://eprint.iacr.org/2014/650
    date: false
    authors:
      -
        ins: S. Jarecki
        org: UC Irvine, CA, USA
      -
        ins: A. Kiayias
        org: University of Athens, Greece
      -
        ins: H. Krawczyk
        org: IBM Research, NY, USA
  SJKS17:
    title:  SPHINX, A Password Store that Perfectly Hides from Itself
    target: https://eprint.iacr.org/2018/695
    date: false
    authors:
      -
        ins: M. Shirvanian
        org: University of Alabama at Birmingham, USA
      -
        ins: S. Jarecki
        org: UC Irvine, CA, USA
      -
        ins: H. Krawczyk
        org: IBM Research, NY, USA
      -
        ins: N. Saxena
        org: University of Alabama at Birmingham, USA
  ECS15:
    title: The pythia PRF service
    target: https://eprint.iacr.org/2015/644.pdf
    date: false
    authors:
      -
        ins: A. Everspaugh
        org: University of Wisconsin–Madison, USA
      -
        ins: R. Chatterjee
        org: University of Wisconsin–Madison, USA
      -
        ins: S. Scott
        org: Royal Holloway, University of London, UK
      -
        ins: A. Juels
        org: Jacobs Institute, Cornell Tech, USA
      -
        ins: T. Ristenpart
        org: Cornell Tech, USA
  TCRSTW21:
    title: A Fast and Simple Partially Oblivious PRF, with Applications
    target: https://eprint.iacr.org/2021/864
    date: false
    authors:
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
  DGSTV18:
    title: Privacy Pass, Bypassing Internet Challenges Anonymously
    target: https://www.degruyter.com/view/j/popets.2018.2018.issue-3/popets-2018-0026/popets-2018-0026.xml
    date: false
    authors:
      -
        ins: A. Davidson
        org: RHUL, UK
      -
        ins: I. Goldberg
        org: University of Waterloo, Canada
      -
        ins: N. Sullivan
        org: Cloudflare, CA, USA
      -
        ins: G. Tankersley
        org: Independent
      -
        ins: F. Valsorda
        org: Independent
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

informative:
  JKX21:
    title: "On the (In)Security of the Diffie-Hellman Oblivious PRF with Multiplicative Blinding"
    target: https://eprint.iacr.org/2021/273
    date: March, 2021
    seriesinfo: PKC'21
    author:
      -
        org: S. Jarecki
        name: Stanislaw Jarecki
      -
        org: H. Krawczyk
        name: Hugo Krawczyk
      -
        org: J. Xu
        name: Jiayu Xu
  keyagreement: DOI.10.6028/NIST.SP.800-56Ar3

--- abstract

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol for
computing the output of a PRF. One party (the server) holds the PRF
secret key, and the other (the client) holds the PRF input. The
'obliviousness' property ensures that the server does not learn anything
about the client's input during the evaluation. The client should also
not learn anything about the server's secret PRF key. Optionally, OPRFs
can also satisfy a notion of 'verifiability' (VOPRF). In this setting, the
client can verify that the server's output is indeed the result of
evaluating the underlying PRF with just a public key. This document
specifies OPRF and VOPRF constructions instantiated within prime-order
groups, including elliptic curves.

--- middle

# Introduction

A pseudorandom function (PRF) F(k, x) is an efficiently computable
function taking a private key k and a value x as input. This function is
pseudorandom if the keyed function K(\_) = F(K, \_) is indistinguishable
from a randomly sampled function acting on the same domain and range as
K(). An oblivious PRF (OPRF) is a two-party protocol between a server
and a client, where the server holds a PRF key k and the client holds
some input x. The protocol allows both parties to cooperate in computing
F(k, x) such that: the client learns F(k, x) without learning anything
about k; and the server does not learn anything about x or F(k, x).
A Verifiable OPRF (VOPRF) is an OPRF wherein the server can prove to the
client that F(k, x) was computed using the key k.

The usage of OPRFs has been demonstrated in constructing a number of
applications: password-protected secret sharing schemes {{JKKX16}};
privacy-preserving password stores {{SJKS17}}; and
password-authenticated key exchange or PAKE {{!I-D.irtf-cfrg-opaque}}. A VOPRF is
necessary in some applications, e.g., the Privacy Pass protocol
{{!I-D.davidson-pp-protocol}}, wherein this VOPRF is used to generate
one-time authentication tokens to bypass CAPTCHA challenges. VOPRFs have
also been used for password-protected secret sharing schemes e.g.
{{JKK14}}.

This document introduces an OPRF protocol built in prime-order groups,
applying to finite fields of prime-order and also elliptic curve (EC)
groups. The protocol has the option of being extended to a VOPRF with
the addition of a NIZK proof for proving discrete log equality
relations. This proof demonstrates correctness of the computation, using
a known public key that serves as a commitment to the server's secret
key. The document describes the protocol, the public-facing API, and its
security properties.

In some applications, there is the need to include an amount of public
metadata into the OPRF protocol. Partially-Oblivious PRFs (POPRF) {{TCRSTW21}}
are used to extend the OPRF functionality to include this public input
(or metadata) in the PRF evaluation.

## Change log

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

# Preliminaries

The (V)OPRF protocol in this document has two primary dependencies:

- `GG`: A prime-order group implementing the API described below in {{pog}},
  with base point defined in the corresponding reference for each group.
  (See {{ciphersuites}} for these base points.)
- `Hash`: A cryptographic hash function that is indifferentiable from a
  Random Oracle, whose output length is Nh bytes long.

{{ciphersuites}} specifies ciphersuites as combinations of `GG` and `Hash`.

## Prime-Order Group Dependency {#pog}

In this document, we assume the construction of an additive, prime-order
group `GG` for performing all mathematical operations. Such groups are
uniquely determined by the choice of the prime `p` that defines the
order of the group. We use `GF(p)` to represent the finite field of
order `p`. For the purpose of understanding and implementing this
document, we take `GF(p)` to be equal to the set of integers defined by
`{0, 1, ..., p-1}`.

The fundamental group operation is addition `+` with identity element
`I`. For any elements `A` and `B` of the group `GG`, `A + B = B + A` is
also a member of `GG`. Also, for any `A` in `GG`, there exists an element
`-A` such that `A + (-A) = (-A) + A = I`. Scalar multiplication is
equivalent to the repeated application of the group operation on an
element A with itself `r-1` times, this is denoted as `r*A = A + ... + A`.
For any element `A`, `p*A=I`. We denote `G` as the fixed generator of
the group. Scalar base multiplication is equivalent to the repeated
application of the group operation `G` with itself `r-1` times, this
is denoted as `ScalarBaseMult(r)`. The set of scalars corresponds to
`GF(p)`. This document uses types `Element` and `Scalar` to denote elements
of the group `GG` and its set of scalars, respectively.

We now detail a number of member functions that can be invoked on a
prime-order group `GG`.

- Order(): Outputs the order of `GG` (i.e. `p`).
- Identity(): Outputs the identity element of the group (i.e. `I`).
- HashToGroup(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to an element of `GG`. The map must ensure that,
  for any adversary receiving `R = HashToGroup(x)`, it is
  computationally difficult to reverse the mapping. This function is optionally
  parameterized by a domain separation tag (DST); see {{ciphersuites}}.
- HashToScalar(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to an element in GF(p). This function is optionally
  parameterized by a DST; see {{ciphersuites}}.
- RandomScalar(): A member function of `GG` that chooses at random a
  non-zero element in GF(p).
- SerializeElement(A): A member function of `GG` that maps a group element `A`
  to a unique byte array `buf` of fixed length `Ne`. The output type of
  this function is `SerializedElement`.
- DeserializeElement(buf): A member function of `GG` that maps a byte array
  `buf` to a group element `A`, or fails if the input is not a valid
  byte representation of an element. This function can raise a
  DeserializeError if deserialization fails or `A` is the identity element
  of the group; see {{input-validation}}.
- SerializeScalar(s): A member function of `GG` that maps a scalar element `s`
  to a unique byte array `buf` of fixed length `Ns`. The output type of this
  function is `SerializedScalar`.
- DeserializeScalar(buf): A member function of `GG` that maps a byte array
  `buf` to a scalar `s`, or fails if the input is not a valid byte
  representation of a scalar. This function can raise a
  DeserializeError if deserialization fails; see {{input-validation}}.

Two functions can be used for generating a (V)OPRF key pair (`skS`, `pkS`)
where `skS` is a non-zero integer less than `p` and `pkS = ScalarBaseMult(skS)`:
`GenerateKeyPair` and `DeriveKeyPair`. `GenerateKeyPair` is a randomized function
that outputs a fresh key pair (`skS`, `pkS`) upon every invocation. `DeriveKeyPair`
is a  deterministic  function that generates private key `skS` from a random byte
string `seed`, which SHOULD have at least `Ns` bytes of entropy, and then
computes `pkS = ScalarBaseMult(skS)`.

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

## Conventions and Terminology

The following conventions are used throughout the document.

- For any object `x`, we write `len(x)` to denote its length in bytes.
- For two byte arrays `x` and `y`, write `x || y` to denote their
  concatenation.
- I2OSP and OS2IP: Convert a byte array to and from a non-negative
  integer as described in {{!RFC8017}}. Note that these functions
  operate on byte arrays in big-endian byte order.

Data structure descriptions use TLS notation {{RFC8446, Section 3}}.

All algorithm descriptions are written in a Python-like pseudocode.
We also use the `CT_EQUAL(a, b)` function to represent constant-time
byte-wise equality between byte arrays `a` and `b`. This function
returns `true` if `a` and `b` are equal, and `false` otherwise.

The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- OPRF: Oblivious Pseudorandom Function.
- VOPRF: Verifiable Oblivious Pseudorandom Function.
- Client: Protocol initiator. Learns pseudorandom function evaluation as
  the output of the protocol.
- Server: Computes the pseudorandom function over a secret key. Learns
  nothing about the client's input.
- NIZK: Non-interactive zero knowledge.
- DLEQ: Discrete Logarithm Equality.

# (V)OPRF Protocol {#protocol}

In this section, we define two OPRF variants: a base mode and verifiable
mode. In the base mode, a client and server interact to compute y =
F(skS, input, info), where input is the client's private input, skS is the
server's private key, info is the optional public input (or metadata)
and y is the OPRF output. The client learns y and the server learns
nothing. In the  verifiable mode, the client also gets proof that the
server used skS in computing the function.

To achieve verifiability, as in the original work of {{JKK14}}, we
provide a zero-knowledge proof that the key provided as input by the
server in the `Evaluate` function is the same key as it used to produce
their public key. As an example of the nature of attacks that this
prevents, this ensures that the server uses the same private key for
computing the VOPRF output and does not attempt to "tag" individual
clients with select keys. This proof must not reveal the server's
long-term private key to the client.

The following one-byte values distinguish between these two modes:

| Mode           | Value |
|:===============|:======|
| modeBase       | 0x00  |
| modeVerifiable | 0x01  |

## Overview {#protocol-overview}

Both participants agree on the mode and a choice of ciphersuite that is
used before the protocol exchange. Once established, the base mode of
the protocol runs to compute `y = F(skS, input, info)` as follows:

~~~
    Client(input, info)                               Server(skS, info)
  ----------------------------------------------------------------------
    blind, blindedElement = Blind(input)

                              blindedElement
                               ---------->

    evaluatedElement, proof  = Evaluate(skS, blindedElement, info)

                             evaluatedElement
                               <----------

  output = Finalize(input, blind, evaluatedElement, blindedElement, info)
~~~

In `Blind` the client generates a blinded element and blinding data. The server
computes the (V)OPRF evaluation in `Evaluation` over the client's blinded token,
and optional public information `info`. In `Finalize` the client unblinds the
server response and produces a byte array corresponding to the output of the OPRF
protocol.

In the verifiable mode of the protocol, the server additionally computes
a proof in Evaluate. The client verifies this proof using the server's
expected public key before completing the protocol and producing the
protocol output.

## Context Setup

Both modes of the OPRF involve an offline setup phase. In this phase,
both the client and server create a context used for executing the
online phase of the protocol. The key pair (`skS`, `pkS`) should be
generated by calling either `GenerateKeyPair` or `DeriveKeyPair`.

The base mode setup functions for creating client and server contexts are below:

~~~
def SetupBaseServer(suite, skS):
  contextString =
    "VOPRF07-" || I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ServerContext(contextString, skS)

def SetupBaseClient(suite):
  contextString =
    "VOPRF07-" || I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ClientContext(contextString)
~~~

The verifiable mode setup functions for creating client and server
contexts are below:

~~~
def SetupVerifiableServer(suite, skS, pkS):
  contextString =
    "VOPRF07-" || I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableServerContext(contextString, skS)

def SetupVerifiableClient(suite, pkS):
  contextString =
    "VOPRF07-" || I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableClientContext(contextString, pkS)
~~~

Each setup function takes a ciphersuite from the list defined in
{{ciphersuites}}. Each ciphersuite has a two-byte field ID used to
identify the suite.

[[RFC editor: please change "VOPRF07" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

## Context APIs {#api}

In this section, we detail the APIs available on the client and server
(V)OPRF contexts. Each API has the following implicit parameters:

- GG, a prime-order group implementing the API described in {{pog}}.
- contextString, a domain separation tag taken from the client or server
  context.


The data types `PrivateInput` and `PublicInput` are opaque byte strings
of arbitrary length no larger than 2^13 octets. `Proof` is a concatenated
sequence of two `SerializedScalar` values, as shown below.

~~~
SerializedScalar Proof[2*Ns];
~~~

### Server Context

The ServerContext encapsulates the context string constructed during
setup and the (V)OPRF key pair. It has three functions, `Evaluate`,
`FullEvaluate` and `VerifyFinalize` described below. `Evaluate` takes
serialized representations of blinded group elements from the client as inputs
and optionally the public metadata input as determined by the server and/or
the public metadata input as sent by the client.

`FullEvaluate` takes PrivateInput values, and it is useful for applications
that need to compute the whole OPRF protocol on the server side only.

`VerifyFinalize` takes PrivateInput values and their corresponding output
digests from `Finalize` as input, and returns true if the inputs match the outputs.

Note that `VerifyFinalize` and `FullEvaluate` are not used in the main OPRF
protocol. They are exposed as an API for building higher-level protocols.

#### Evaluate

~~~
Input:

  Scalar skS
  SerializedElement blindedElement
  PublicInput info

Output:

  SerializedElement evaluatedElement

Errors: DeserializeError

def Evaluate(skS, blindedElement, info):
  R = GG.DeserializeElement(blindedElement)
  context = "Context-" || contextString ||
            I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)
  t = skS + m
  Z = (t^(-1)) * R
  evaluatedElement = GG.SerializeElement(Z)

  return evaluatedElement
~~~

#### FullEvaluate

~~~
Input:

  Scalar skS
  PrivateInput input
  PublicInput info

Output:

  opaque output[Nh]

def FullEvaluate(skS, input):
  P = GG.HashToGroup(input)
  context = "Context-" || contextString ||
            I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)
  t = skS + m
  T = (t^(-1)) * P
  issuedElement = GG.SerializeElement(T)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(issuedElement), 2) || issuedElement ||
              I2OSP(len(finalizeDST), 2) || finalizeDST

  return Hash(hashInput)
~~~

#### VerifyFinalize

~~~
Input:

  Scalar skS
  PrivateInput input
  opaque output[Nh]
  PublicInput info

Output:

  boolean valid

def VerifyFinalize(skS, input, output, info):
  T = GG.HashToGroup(input)
  element = GG.SerializeElement(T)
  issuedElement = Evaluate(skS, [element], info)
  E = GG.SerializeElement(issuedElement)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(E), 2) || E ||
              I2OSP(len(finalizeDST), 2) || finalizeDST

  digest = Hash(hashInput)

  return CT_EQUAL(digest, output)
~~~

### VerifiableServerContext

The VerifiableServerContext extends the base ServerContext with an
augmented `Evaluate()` function. This function produces a proof that
`skS` was used in computing the result. It makes use of the helper
functions `GenerateProof` and `ComputeComposites`, described below.

#### Evaluate

~~~
Input:

  Scalar skS
  Element pkS
  SerializedElement blindedElement
  PublicInput info

Output:

  SerializedElement evaluatedElement
  Proof proof

Errors: DeserializeError

def Evaluate(skS, pkS, blindedElement, info):
  R = GG.DeserializeElement(blindedElement)
  context = "Context-" || contextString ||
            I2OSP(len(info), 2) || info ||
  m = GG.HashToScalar(context)
  t = skS + m
  Z = (t^(-1)) * R

  U = ScalarBaseMult(t)
  proof = GenerateProof(t, G, U, Z, R)
  evaluatedElement = GG.SerializeElement(Z)
  return evaluatedElement, proof
~~~

The helper functions `GenerateProof` and `ComputeComposites` are defined
below.

#### GenerateProof

~~~
Input:

  Scalar k
  Element A
  Element B
  Element C
  Element D

Output:

  Proof proof

def GenerateProof(k, A, B, C, D)
  Cs = [C]
  Ds = [D]
  a = ComputeCompositesFast(k, B, Cs, Ds)

  r = GG.RandomScalar()
  M = a[0]
  Z = a[1]

  t2 = r * A
  t3 = r * M

  Bm = GG.SerializeElement(B)
  a0 = GG.SerializeElement(M)
  a1 = GG.SerializeElement(Z)
  a2 = GG.SerializeElement(t2)
  a3 = GG.SerializeElement(t3)

  challengeDST = "Challenge-" || contextString
  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  c = GG.HashToScalar(h2Input)
  s = (r - c * k) mod p
  proof = [GG.SerializeScalar(c), GG.SerializeScalar(s)]

  return proof
~~~

##### Batching inputs

Unlike other functions, `ComputeComposites` takes lists of inputs,
rather than a single input. Applications can take advantage of this
functionality by invoking `GenerateProof` on batches of inputs to
produce a combined, constant-size proof. (In the pseudocode above,
the single inputs `blindedElement` and `evaluatedElement` are passed as
one-item lists to `ComputeComposites`.)

In particular, servers can produce a single, constant-sized proof for N
client inputs sent in a single request, rather than one proof per client
input. This optimization benefits clients and servers since it amortizes
the cost of proof generation and bandwidth across multiple requests.

##### Fresh Randomness

We note here that it is essential that a different `r` value is used for
every invocation. If this is not done, then this may leak `skS` as is
possible in Schnorr or (EC)DSA scenarios where fresh randomness is not
used.

#### ComputeComposites

The definition of `ComputeComposites` is given below. This function is
used both on generation and verification of the proof.

~~~
Input:

  Element B
  Element Cs[m]
  Element Ds[m]

Output:

  Element composites[2]

def ComputeComposites(B, Cs, Ds):
  Bm = GG.SerializeElement(B)
  seedDST = "Seed-" || contextString
  compositeDST = "Composite-" || contextString

  h1Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(seedDST), 2) || seedDST
  seed = Hash(h1Input)

  M = GG.Identity()
  Z = GG.Identity()
  for i = 0 to m-1:
    Ci = GG.SerializeElement(Cs[i])
    Di = GG.SerializeElement(Ds[i])
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(Ci), 2) || Ci ||
              I2OSP(len(Di), 2) || Di ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    M = di * Cs[i] + M
    Z = di * Ds[i] + Z

 return [M, Z]
~~~

If the private key is known, as is the case for the server, this function
can be optimized as shown in `ComputeCompositesFast` below.

~~~
Input:

  Scalar k
  Element B
  Element Cs[m]
  Element Ds[m]

Output:

  Element composites[2]

def ComputeCompositesFast(k, B, Cs, Ds):
  Bm = GG.SerializeElement(B)
  seedDST = "Seed-" || contextString
  compositeDST = "Composite-" || contextString

  h1Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(seedDST), 2) || seedDST
  seed = Hash(h1Input)

  M = GG.Identity()
  for i = 0 to m-1:
    Ci = GG.SerializeElement(Cs[i])
    Di = GG.SerializeElement(Ds[i])
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(Ci), 2) || Ci ||
              I2OSP(len(Di), 2) || Di ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    M = di * Cs[i] + M

  Z = k * M

 return [M, Z]
~~~

### Client Context {#base-client}

The ClientContext encapsulates the context string constructed during
setup. It has two functions, `Blind()` and `Finalize()`, as described
below. It also has an internal function, `Unblind()`, which is used
by `Finalize`. The implementation of these functions varies depending
on the mode.

#### Blind

Blinding is done multiplicatively.

`Blind` is implemented as follows:

~~~
Input:

  PrivateInput input

Output:

  Scalar blind
  SerializedElement blindedElement

def Blind(input):
  blind = GG.RandomScalar()
  P = GG.HashToGroup(input)
  blindedElement = GG.SerializeElement(blind * P)

  return blind, blindedElement
~~~

The inverse `Unblind` is implemented as follows.

~~~
Input:

  Scalar blind
  SerializedElement evaluatedElement

Output:

  SerializedElement unblindedElement

Errors: DeserializeError

def Unblind(blind, evaluatedElement):
  Z = GG.DeserializeElement(evaluatedElement)
  N = (blind^(-1)) * Z
  unblindedElement = GG.SerializeElement(N)

  return unblindedElement
~~~

#### Finalize

`Finalize` depends on the internal `Unblind` function. In this mode, `Finalize`
does not include all inputs listed in {{protocol-overview}}. These additional
inputs are only useful for the verifiable mode, described in {{verifiable-finalize}}.

~~~
Input:

  PrivateInput input
  Scalar blind
  SerializedElement evaluatedElement
  PublicInput info

Output:

  opaque output[Nh]

def Finalize(input, blind, evaluatedElement, info):
  unblindedElement = Unblind(blind, evaluatedElement)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              I2OSP(len(finalizeDST), 2) || finalizeDST
  return Hash(hashInput)
~~~

### VerifiableClientContext {#verifiable-client}

The VerifiableClientContext extends the base ClientContext with the
desired server public key `pkS` with an augmented `Unblind()` function.
This function verifies an evaluation proof using `pkS`. It makes use of
the helper function `ComputeComposites` described above. It has one
helper function, `VerifyProof()`, defined below.

#### VerifyProof

This algorithm outputs a boolean `verified` which indicates whether the
proof inside of the evaluation verifies correctly, or not.

~~~
Input:

  Element A
  Element B
  Element C
  Element D
  Proof proof

Output:

  boolean verified

def VerifyProof(A, B, C, D, proof):
  Cs = [C]
  Ds = [D]

  a = ComputeComposites(B, Cs, Ds)
  c = GG.DeserializeScalar(proof[0])
  s = GG.DeserializeScalar(proof[1])

  M = a[0]
  Z = a[1]

  t2 = ((s * A) + (c * B))
  t3 = ((s * M) + (c * Z))

  Bm = GG.SerializeElement(B)
  a0 = GG.SerializeElement(M)
  a1 = GG.SerializeElement(Z)
  a2 = GG.SerializeElement(t2)
  a3 = GG.SerializeElement(t3)

  challengeDST = "Challenge-" || contextString
  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  expectedC  = GG.HashToScalar(h2Input)

  return CT_EQUAL(expectedC, c)
~~~

#### Verifiable Unblind {#verifiable-unblind}

The inverse `VerifiableUnblind` is implemented as follows. This function
can raise an exception if element deserialization or proof verification
fails.

~~~
Input:

  Scalar blind
  SerializedElement evaluatedElement
  SerializedElement blindedElement
  Element pkS
  Scalar proof
  PublicInput info

Output:

  SerializedElement unblindedElement

Errors: DeserializeError, VerifyError

def VerifiableUnblind(blind, evaluatedElement, blindedElement, pkS, proof, info):
  context = "Context-" || contextString ||
            I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)

  R = GG.DeserializeElement(blindedElement)
  Z = GG.DeserializeElement(evaluatedElement)

  T = ScalarBaseMult(m)
  U = T + pkS
  if VerifyProof(G, U, Z, R, proof) == false:
    raise VerifyError

  N = (blind^(-1)) * Z
  unblindedElement = GG.SerializeElement(N)

  return unblindedElement
~~~

#### Verifiable Finalize {#verifiable-finalize}

~~~
Input:

  PrivateInput input
  Scalar blind
  SerializedElement evaluatedElement
  SerializedElement blindedElement
  Element pkS
  Scalar proof
  PublicInput info


Output:

  opaque output[Nh]

def VerifiableFinalize(input, blind, blindedPublicKey, evaluatedElement, blindedElement, pkS, proof, info):
  unblindedElement = VerifiableUnblind(blind, evaluatedElement, blindedElement, pkS, proof, info)

  finalizeDST = "Finalize-" || contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              I2OSP(len(finalizeDST), 2) || finalizeDST
  return Hash(hashInput)
~~~

# Ciphersuites {#ciphersuites}

A ciphersuite (also referred to as 'suite' in this document) for the protocol
wraps the functionality required for the protocol to take place. This
ciphersuite should be available to both the client and server, and agreement
on the specific instantiation is assumed throughout. A ciphersuite contains
instantiations of the following functionalities:

- `GG`: A prime-order group exposing the API detailed in {{pog}}, with base
  point defined in the corresponding reference for each group. Each group also
  specifies HashToGroup, HashToScalar, and serialization functionalities. For
  HashToGroup, the domain separation tag (DST) is constructed in accordance
  with the recommendations in {{!I-D.irtf-cfrg-hash-to-curve}}, Section 3.1.
  For HashToScalar, each group specifies an integer order that is used in
  reducing integer values to a member of the corresponding scalar field.
- `Hash`: A cryptographic hash function that is indifferentiable from a
  Random Oracle, whose output length is Nh bytes long.

This section specifies ciphersuites with supported groups and hash functions.
For each ciphersuite, contextString is that which is computed in the Setup
functions.

Applications should take caution in using ciphersuites targeting P-256
and ristretto255. See {{cryptanalysis}} for related discussion.

## OPRF(ristretto255, SHA-512)

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

## OPRF(decaf448, SHAKE-256)

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

## OPRF(P-256, SHA-256)

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

## OPRF(P-384, SHA-512)

- Group: P-384 (secp384r1) {{x9.62}}
  - HashToGroup(): Use hash_to_curve with suite P384_XMD:SHA-512_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} and DST =
    "HashToGroup-" || contextString.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using L = 72, `expand_message_xmd` with SHA-512,
    DST = "HashToScalar-" || contextString, and
    prime modulus equal to `Order()`.
  - Serialization: Elements are serialized as Ne = 49 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 48 byte strings by fully reducing the value modulo `Order()` and in big-endian
    order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0004

## OPRF(P-521, SHA-512)

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

# Application Considerations {#apis}

This section describes considerations for applications, including explicit error
treatment and public metadata representation.

## Error Considerations

Some VOPRF APIs specified in this document are fallible. For example, `Finalize`
and `Evaluate` can fail if any element received from the peer fails deserialization.
The explicit errors generated throughout this specification, along with the
conditions that lead to each error, are as follows:

- `VerifyError`: VOPRF proof verification failed; {{verifiable-unblind}}.
- `DeserializeError`: Group element or scalar deserialization failure; {{pog}}.

The errors in this document are meant as a guide to implementors. They are not
an exhaustive list of all the errors an implementation might emit. For example,
implementations might run out of memory and return a corresponding error.

## Public Metadata

The optional and public `info` string included in the protocol allows clients
and servers to cryptographically bind additional data to the VOPRF output. This
metadata is known to both parties at the start of the protocol. It is RECOMMENDED
that this metadata be constructed with some type of higher-level domain separation
to avoid cross protocol attacks or related issues. For example, protocols using
this construction might ensure that the metadata uses a unique, prefix-free encoding.
See {{I-D.irtf-cfrg-hash-to-curve, Section 10.4}} for further discussion on
constructing domain separation values.

# Security Considerations {#sec}

This section discusses the cryptographic security of our protocol, along
with some suggestions and trade-offs that arise from the implementation
of an OPRF.

## Security Properties {#properties}

The security properties of an OPRF protocol with functionality y = F(k,
x, t) include those of a standard PRF. Specifically:

- Pseudorandomness: F is pseudorandom if the output y = F(k,x, t) on any
  input x is indistinguishable from uniformly sampling any element in
  F's range, for a random sampling of k.

In other words, consider an adversary that picks inputs x from the
domain of F and evaluates F on (k,x, t) (without knowledge of randomly
sampled k). Then the output distribution F(k,x, t) is indistinguishable
from the output distribution of a randomly chosen function with the same
domain and range.

A consequence of showing that a function is pseudorandom, is that it is
necessarily non-malleable (i.e. we cannot compute a new evaluation of F
from an existing evaluation). A genuinely random function will be
non-malleable with high probability, and so a pseudorandom function must
be non-malleable to maintain indistinguishability.

An OPRF protocol must also satisfy the following property:

- Oblivious: The server must learn nothing about the client's input or
  the output of the function. In addition, the client must learn nothing
  about the server's private key.

Essentially, obliviousness tells us that, even if the server learns the
client's input x at some point in the future, then the server will not
be able to link any particular OPRF evaluation to x. This property is
also known as unlinkability {{DGSTV18}}.

Optionally, for any protocol that satisfies the above properties, there
is an additional security property:

- Verifiable: The client must only complete execution of the protocol if
  it can successfully assert that the OPRF output it computes is
  correct. This is taken with respect to the OPRF key held by the
  server.

Any OPRF that satisfies the 'verifiable' security property is known as a
verifiable OPRF, or VOPRF for short. In practice, the notion of
verifiability requires that the server commits to the key before the
actual protocol execution takes place. Then the client verifies that the
server has used the key in the protocol using this commitment. In the
following, we may also refer to this commitment as a public key.

## Cryptographic Security {#cryptanalysis}

Below, we discuss the cryptographic security of the (V)OPRF protocol
from {{protocol}}, relative to the necessary cryptographic assumptions
that need to be made.

### Computational Hardness Assumptions {#assumptions}

Each assumption states that the problems specified below are
computationally difficult to solve in relation to a particular choice of
security parameter `sp`.

Let GG = GG(sp) be a group with prime-order p, and let GF(p) be a finite
field of order p.

#### Discrete-log (DL) Problem {#dl}

Given G, a generator of GG, and H = hG for some h in GF(p); output h.

#### Decisional Diffie-Hellman (DDH) Problem {#ddh}

Sample uniformly at random d in {0,1}. Given (G, aG, bG, C), where

- G is a generator of GG;
- a,b are elements of GF(p);
- if d == 0: C = abG; else: C is sampled uniformly at random from GG.

Output d' == d.

### Protocol Security {#protocol-sec}

Our OPRF construction is based on the VOPRF construction known as
2HashDH-NIZK given by {{JKK14}}; essentially without providing
zero-knowledge proofs that verify that the output is correct. Our VOPRF
construction is identical to the {{JKK14}} construction, except that we
can optionally perform multiple VOPRF evaluations in one go, whilst only
constructing one NIZK proof object. This is enabled using an established
batching technique.

Consequently, the cryptographic security of our construction is based on
the assumption that the One-More Gap DH is computationally difficult to
solve.

The (N,Q)-One-More Gap DH (OMDH) problem asks the following.

~~~
    Given:
    - G, k * G, and (G_1, ... , G_N), all elements of GG;
    - oracle access to an OPRF functionality using the key k;
    - oracle access to DDH solvers.

    Find Q+1 pairs of the form below:

    (G_{j_s}, k * G_{j_s})

    where the following conditions hold:
      - s is a number between 1 and Q+1;
      - j_s is a number between 1 and N for each s;
      - Q is the number of allowed queries.
~~~

The original paper {{JKK14}} gives a security proof that the
2HashDH-NIZK construction satisfies the security guarantees of a VOPRF
protocol {{properties}} under the OMDH assumption in the universal
composability (UC) security model.

### Q-Strong-DH Oracle {#qsdh}

A side-effect of our OPRF design is that it allows instantiation of a
oracle for constructing Q-strong-DH (Q-sDH) samples. The Q-Strong-DH
problem asks the following.

~~~
    Given G1, G2, h*G2, (h^2)*G2, ..., (h^Q)*G2; for G1 and G2
    generators of GG.

    Output ( (1/(k+c))*G1, c ) where c is an element of GF(p)
~~~

The assumption that this problem is hard was first introduced in
{{BB04}}. Since then, there have been a number of cryptanalytic studies
that have reduced the security of the assumption below that implied by
the group instantiation (for example, {{BG04}} and {{Cheon06}}). In
summary, the attacks reduce the security of the group instantiation by
log\_2(Q)/2 bits. Note that the attacks only work in situations where Q
divides p-1 or p+1, where p is the order of the prime-order group used
to instantiate the OPRF.

As an example, suppose that a group instantiation is used that provides
128 bits of security against discrete log cryptanalysis. Then an
adversary with access to a Q-sDH oracle and makes Q=2^20 queries can
reduce the security of the instantiation by log\_2(2^20)/2 = 10 bits. Launching an attack would require
2^(p/2-log\_2(Q)/2) bits of memory.

Notice that it is easy to instantiate a Q-sDH oracle using the OPRF
functionality that we provide. A client can just submit sequential
queries of the form (G, k * G, (k^2)G, ..., (k^(Q-1))G), where each
query is the output of the previous interaction. This means that any
client that submits Q queries to the OPRF can use the aforementioned
attacks to reduce the security of the group instantiation by
(log\_2(Q)/2) bits.

Recall that from a malicious client's perspective, the adversary wins if
they can distinguish the OPRF interaction from a protocol that computes
the ideal functionality provided by the PRF.

### Implications for Ciphersuite Choices

The OPRF instantiations that we recommend in this document are informed
by the cryptanalytic discussion above. In particular, choosing elliptic
curves configurations that describe 128-bit group instantiations would
appear to in fact instantiate an OPRF with 128-(log\_2(Q)/2) bits of
security. Moreover, such attacks are only possible for those certain
applications where the adversary can query the OPRF directly.
In applications where such an oracle is not made available this security loss does not apply.

In most cases, it would require an informed and persistent attacker to
launch a highly expensive attack to reduce security to anything much
below 100 bits of security. We see this possibility as something that
may result in problems in the future. For applications that admit the
aforementioned oracle functionality, and that cannot tolerate discrete logarithm
security of lower than 128 bits, we recommend only implementing
ciphersuites with IDs 0x0002, 0x0004, and 0x0005.

## Domain Separation {#domain-separation}

Applications SHOULD construct input to the protocol to provide domain
separation. Any system which has multiple (V)OPRF applications should
distinguish client inputs to ensure the OPRF results are separate.
Guidance for constructing info can be found in
{{!I-D.irtf-cfrg-hash-to-curve}}; Section 3.1.

## Element and Scalar Validation {#input-validation}

The DeserializeElement function recovers a group element from an arbitrary
byte array. This function validates that the element is a proper member
of the group and is not the identity element, and returns an error if either
condition is not met.

For P-256, P-384, and P-521 ciphersuites, this function performs partial
public-key validation as defined in Section 5.6.2.3.4 of {{keyagreement}}.
This includes checking that the coordinates are in the correct range, that
the point is on the curve, and that the point is not the point at infinity.
If these checks fail, deserialization returns an error.

For ristretto255 and decaf448, elements are deserialized by invoking the Decode
function from {{RISTRETTO, Section 4.3.1}} and {{RISTRETTO, Section 5.3.1}}, respectively,
which returns false if the element is invalid. If this function returns false,
deserialization returns an error.

The DeserializeScalar function recovers a scalar field element from an arbitrary
byte array. Like DeserializeElement, this function validates that the element
is a member of the scalar field and returns an error if this condition is not met.

For P-256, P-384, and P-521 ciphersuites, this function ensures that the input,
when treated as a big-endian integer, is a value between 0 and `Order()`. For
ristretto255 and decaf448, this function ensures that the input, when treated as
a little-endian integer, is a valud between 0 and `Order()`.

## Hashing to Group

A critical requirement of implementing the prime-order group using
elliptic curves is a method to instantiate the function
`GG.HashToGroup`, that maps inputs to group elements. In the elliptic
curve setting, this deterministically maps inputs x (as byte arrays) to
uniformly chosen points on the curve.

In the security proof of the construction Hash is modeled as a random
oracle. This implies that any instantiation of `GG.HashToGroup` must be
pre-image and collision resistant. In {{ciphersuites}} we give
instantiations of this functionality based on the functions described in
{{!I-D.irtf-cfrg-hash-to-curve}}. Consequently, any OPRF implementation
must adhere to the implementation and security considerations discussed
in {{!I-D.irtf-cfrg-hash-to-curve}} when instantiating the function.

## Blinding Considerations {#blind-considerations}

This document makes use of one type of blinding variants: multiplicative.
Blinding may also be done additively. However, the choice of blinding
mechanism has security implications. {{JKX21}} analyze the security
properties of different blinding mechanisms. The results can be
summarized as follows:

- Multiplicative blinding is safe for all applications.
- Additive blinding is possibly unsafe, unless one of the following conditions
  are met:
    - The client has a certified copy of the server public key (as is the case
      in the verifiable mode);
    - The client input has high entropy; and
    - The client mixes the public key into the OPRF evaluation.

To avoid security issues, where some of the above conditions may not be met,
this specification use of multiplicative blinding. This is because it is
not known if the server public key is available or if the client input has
high entropy.

## Timing Leaks

To ensure no information is leaked during protocol execution, all
operations that use secret data MUST run in constant time. Operations that
SHOULD run in constant time include all prime-order group operations and
proof-specific operations (`GenerateProof()` and `VerifyProof()`).

## Key Rotation {#key-rotation}

Since the server's key is critical to security, the longer it is exposed
by performing (V)OPRF operations on client inputs, the longer it is
possible that the key can be compromised. For example, if the key is kept
in circulation for a long period of time, then it also allows the
clients to make enough queries to launch more powerful variants of the
Q-sDH attacks from {{qsdh}}.

To combat attacks of this nature, regular key rotation should be
employed on the server-side. A suitable key-cycle for a key used to
compute (V)OPRF evaluations would be between one week and six months.

### Parameter Commitments

For some applications, it may be desirable for the server to bind tokens to
certain parameters, e.g., protocol versions, ciphersuites, etc. To
accomplish this, the server should use a distinct scalar for each parameter
combination. Upon redemption of a token T from the client, the server can
later verify that T was generated using the scalar associated with the
corresponding parameters.

# Acknowledgements

This document resulted from the work of the Privacy Pass team
{{PrivacyPass}}. The authors would also like to acknowledge helpful
conversations with Hugo Krawczyk. Eli-Shaoul Khedouri provided
additional review and comments on key consistency. Daniel Bourdrez,
Tatiana Bradley, Sofia Celi, Frank Denis, and Bas Westerbaan also
provided helpful input and contributions to the document.

--- back

# Test Vectors

This section includes test vectors for the (V)OPRF protocol specified
in this document. For each ciphersuite specified in {{ciphersuites}},
there is a set of test vectors for the protocol when run in the base
mode and verifiable mode. Each test vector lists the batch size for
the evaluation. Each test vector value is encoded as a hexadecimal
byte string. The label for each test vector value is described below.

- "Input": The secret client input, an opaque byte string.
- "Info": The public info, an opaque byte string.
- "Blind": The blind value output by `Blind()`, a serialized `Scalar`
  of `Ns` bytes long.
- "BlindedElement": The blinded value output by `Blind()`, a serialized
  `Element` of `Ne` bytes long.
- "EvaluatedElement": The evaluated element output by `Evaluate()`,
  a serialized `Element` of `Ne` bytes long.
- "EvaluationProofC": The "c" component of the Evaluation proof (only
  listed for verifiable mode test vectors), a serialized `Scalar` of
  `Ns` bytes long.
- "EvaluationProofS": The "s" component of the Evaluation proof (only
  listed for verifiable mode test vectors), a serialized `Scalar` of
  `Ns` bytes long.
- "Output": The OPRF output, a byte string of length `Nh` bytes.

Test vectors with batch size B > 1 have inputs separated by a comma
",". Applicable test vectors will have B different values for the
"Input", "Blind", "BlindedElement", "EvaluationElement", and
"Output" fields.

Base mode and verifiable mode uses multiplicative blinding.

The server key material, `pkSm` and `skSm`, are listed under the mode for
each ciphersuite. Both `pkSm` and `skSm` are the serialized values of
`pkS` and `skS`, respectively, as used in the protocol. Each key pair
is derived from a `seed`, which is listed as well, using the following
implementation of `DeriveKeyPair`:

~~~
def DeriveKeyPair(mode, suite, seed):
  skS = GG.HashToScalar(seed, DST = "HashToScalar-" || contextString)
  pkS = ScalarBaseMult(skS)
  return skS, pkS
~~~

## OPRF(ristretto255, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1
701
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = fc20e03aff3a9de9b37e8d35886ade11ec7d85c2a1fb5bb0b16
86c64e07ac467
EvaluationElement = 3491a2fef9498ee83e9b9e1bf96beb3a502ed4a9ceea25a5
478da4b00d906d58
Output = 154204aeed3fd31fc3851601b20dc101351bfeb3012eeadb9e06089ce5a
3f265712691189f61e9df1484c97baed3333bb8e162a58ca75bc2aa5ebbf760f6b1f
d
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 483d4f39de5ff77fa0f9a0ad2334dd5bf87f2cda868539d21de
67ce49e7d1536
EvaluationElement = 80156a4f38a14bd57c2a09e0f5d6a3e573fedbb6bfbe5a04
fd6beac15c0f9d7c
Output = 81152ae5ebe08913fd31baa97b4f009e297aafc1521a216c2764daee013
b14023fefb81e1e5bbaaae27d35693fb1074af19a93adfa48c5e0f3a4f7884f8d70d
b
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = ac37d5850510299406ea8eb8fa226a7bfc2467a4b070d6c7bf667948b9600
b00
pkSm = 0c0254e22063cae3e1bae02fb6fa20882664a117c0278eda6bda3372c0dd9
860
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 3a0a53f2c57e5ee0d89e394087f8e5f95b24159db01c31933a0
7f0e6414c954d
EvaluationElement = 58ee977e4c06b5e6c42556d3ad48948396f2240b63d1d0f9
4a3ac06b17b05639
EvaluationProofC = 1c796617a6ca313b259d3eed92bd2ef3f26f7385f4231e0e5
9776e5a79051a00
EvaluationProofS = c947e89714dabdaf2843dbd7d61a5097fcf50628c0aa7e841
a7ad77976e3ad05
Output = f9896674714f95814ebc74d204ddb30beb8c0854f2eaaa288bb5f8e86d5
982423cec1d8329e63b40891e218fd37d7d6f8d4e348b2d1f0c9e3aaf1b24486b8d5
6
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = a86dd4544d0f3ea973926054230767dff16016215f2d73f26d3
f86a81f38cf1a
EvaluationElement = 2e37fcfc896e16069f37db03cf2c76f72beaa5475f3945e1
9a4c27b79e63f702
EvaluationProofC = c3255ca2f6dd12fd1daf70e01abc34f27e74ff6d5b8a0dab1
02ec40797af3509
EvaluationProofS = ea7e35d98fed60b086ecb0e2a637324cf20cf2ce988751e34
bd17937dfb60602
Output = ed40e4ee84c628729b1c900516373e8432fca1e8d838d5a697a703f4924
fdd93efe2f8b49aad53466fc78341f9f1923f26b17869af7eefdee8511179abaa579
a
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0
d50f,533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0
c
BlindedElement = c24645d6378a4a86ec4682a8d86f368b1e7db870fd709a45102
492bcdc17e904,0e5ec78f839a8b6e86999bc180602690a4daae57bf5d7f827f3d40
2f56cc6c51
EvaluationElement = 6a6eea6a13fd54c8ddae5d1aa98c28f573a291fd26ce136c
4f9a8e01ccdc1975,c4055ee95d9f3cb271d05eb37921b97ac032910d68438549cb7
be90b0a1e9f6c
EvaluationProofC = bfcc17103ae2b08c4e644eec0ce60edfdf777f95a1419ada8
ec444b74076df0f
EvaluationProofS = a4c3f584c606d85c81a8c6dfcc6741b27764ae0422b1b3791
116a5d5ce11de07
Output = f9896674714f95814ebc74d204ddb30beb8c0854f2eaaa288bb5f8e86d5
982423cec1d8329e63b40891e218fd37d7d6f8d4e348b2d1f0c9e3aaf1b24486b8d5
6,ed40e4ee84c628729b1c900516373e8432fca1e8d838d5a697a703f4924fdd93ef
e2f8b49aad53466fc78341f9f1923f26b17869af7eefdee8511179abaa579a
~~~

## OPRF(decaf448, SHAKE-256)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 78f2622804104209f7e015370ff98f4a3cbf311e6784e9f4944f8a252dc08
e916d9ab1a60dc905f0e56631903ecd4ae6e15291776d61460b
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = d1080372f0fcf8c5eace50914e7127f576725f215cc7c111673c635ce668
bbbb9b50601ad89b358ab8c23ed0b6c9d040365ec9d060868714
BlindedElement = 984e0a443ee194090737df4afb402253f216b77650c91d252b6
638e1179723d51a4154b88eae396f1320f5df3c4b17f779516c456e364bd1
EvaluationElement = 844d456269020100f4083fdc22406bfa9e5a515788ed113a
0e4597edd3b42e41927c1167e305e0620417900c325ad94c406689b6c66ea981
Output = 9cb3180414f79dff6e79acf780ec2b99edda0a8f5c137a12b50e4744b18
17e8e703691997acf2c5c4ae2073ee75a0d0de9327a2516aca613a29ff92835121ea
9
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = aed1ffa44fd8f0ed16373606a3cf7df589cca86d8ea1abbf5768771dbef3
d401c74ae55ba1e28b9565e1e4018eb261a14134a4ce60c1c718
BlindedElement = 4aa751f84b2634b73efa364b03e60b92b84f457576e6b369eea
b76140e3859d10d2e98174f13f5a2c70670529ccf093d5f1aaf355b4f830b
EvaluationElement = 10c9bfa06cf340aa22130d557d58b814db6d40035223d6bb
8d7013b647e074ed90b62cbaf9d41aa38faffd62f94a6c3e3b6751affc92aba9
Output = bbd55b12a9b568d6c6cc793c69c25ccaadc92f77ad2739c9b3f46a84715
48763ae4ce61f16c0630f066daf7dfb10555b4178b1633a6bd9c66dcf75d68d15c5e
a
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 9eb722f7fee9f61f24ad31bc42309f73648cf4393929e8f5f333fe10c6975
c827a1eba4e03ae2fa8735db2f63f6c98c7af6010e64c81f535
pkSm = b6e2751176d57836fe1dfbdbbdc78a1b5c5a52f831226c9d8dfdf5daf8f46
6e310e80978e9b81c387f5bc85cc7ef5567f4dd3ba7674579a2
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 4c936db1779a621b6c71475ac3111fd5703a59b713929f36dfd1e892a7fe
814479c93d8b4b6e11d1f6fe5351e51457b665fa7b76074e531f
BlindedElement = d0b8e2eecad2816d45c1f8a072fe6db77d18f4b26f0889c98e2
ef856ac5df82090c1fbeac9c8e732f192b66c3b4c3f1e446ab8910c86be2f
EvaluationElement = bab09d803c10650384b77c99f3fdcdb6597b91cf58995c90
55aa0c9b4fdcf15d037699e53d97f5b15ef8f6bd37b1f2df7669ee1df95b5950
EvaluationProofC = 01ef94b5619618195891ea846192dda33d0c5df8edb52297e
6d68d7aa5ba25360a63880ab1ed1785a100a3d934e2144854d47a9d3e861201
EvaluationProofS = e089a8bcc0d26fcf5c6c54a6c4b39723a1bf72808f0b7c59e
24dc77fe1e11ff365de3438671d5924e757c7e8f59332ba7079e1471e5b052a
Output = 3f96df31e26b0f2eade6c4743008d480b11193e5e366ca0110060f14ec4
55bd68b9d2bd38923cce9daeba4a4eb0f18ffad7691bcc469f5595c0bc16cb9396a4
3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15b3355179392f40c3d5a15f0d5ffc354e340454ec779f575e4573a3886a
b5e57e4da2985cea9e32f6d95539ce2c7189e1bd7462e8c5483a
BlindedElement = 0e7ddd85c8bc5382e908241c6151afe23a41e0396759b5e38a9
affd996cd822bca242a499793555fc15f07bffdaaa93b42568b307fbdca0f
EvaluationElement = 4a84fa5d8922900781000ef23123a6795bf1b8dd3c55f420
3864cb865ec59cf1f8191b062d1b6da777166084a58d327ccdea4213eff440b7
EvaluationProofC = fd059530976465a099fa6c168e1373fb5a8ffc2344fcf8563
7db83d7506751758b6a46994be3f407917f67bec790a7a81d7d0d585f153b3b
EvaluationProofS = 152872327401e5f417c78b590adf9acf6a442e42b5ef6ff52
49835ff78b79e77b4dbe4d5d3cb107f3762f4102748ef3accbf3448c10bc227
Output = 05e6e7a9e14602a02edd247835327af372e6cb4c53a8891ae0db7c51e86
17b12633b29af3d48219a66d718b57f01778e00e4cfef9944ef85942067766fa6393
9
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 614bb578f29cc677ea9e7aea3e4839413997e020f9377b63c13584156a09
a46dd2a425c41eac0e313a47e99d05df72c6e1d58e6592577a0d,4c115060bca87db
7d73e00cbb8559f84cb7a221b235b0950a0ab553f03f10e1386abe954011b7da62bb
6599418ef90b5d4ea98cc28aff517
BlindedElement = 5e481a4d7eaa5bab831f53f9a6311851dafd4318c6462eed4f6
15004afdb082da2f99670b0963985faac21c30eea19aacfc441412edb4c0b,8e043b
9b7afeafa07e39d9b8b88957ff07d69124b1a2b841e18c9ffb52ebf0c25144eb2501
a1d7983a44604f33a36e925eebc9bec65d9c54
EvaluationElement = be14dd5f3fbda46c8a93ea1c3a312bf4aef90381b7078969
ad4f5678b6ab033772aaad9cb7b3ef3be904989ba1ca068899f40553cd38a80a,60d
242edda8d6a0cac995b5323747b1e1e9a46f8507e768712eca2c0405ff35f00bdd50
76d330fe2856113c498d533dbecc351666dc89942
EvaluationProofC = 9c03d6c4e90c60f647a94f978de7806d1eab5aba53cc8cc4f
b8cf180b20bd5b9eca4bf3e00b77bdaf2232ac47c41693206c78254cd10da1e
EvaluationProofS = 8a2929dbb7519e6974576a2882a884be0b3baced57ea19a3e
f03a34bf56612ec89969507ce9e5db5818664b6e05df03dbe9b9137d13cca20
Output = 3f96df31e26b0f2eade6c4743008d480b11193e5e366ca0110060f14ec4
55bd68b9d2bd38923cce9daeba4a4eb0f18ffad7691bcc469f5595c0bc16cb9396a4
3,05e6e7a9e14602a02edd247835327af372e6cb4c53a8891ae0db7c51e8617b1263
3b29af3d48219a66d718b57f01778e00e4cfef9944ef85942067766fa63939
~~~

## OPRF(P-256, SHA-256)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = a1b2355828f2c76de6749af9d093bd9fe0f2cada3ec653cd9a6d3126a7a78
27b
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 5d9e7f6efd3093c32ecceabd57fb03cf760c926d2a7bfa265babf29ec98a
f0d0
BlindedElement = 03e3c379698da853d9844098fa0ac676970d5ec24167b598714
cd2ee188604ddd2
EvaluationElement = 02e76f1591188e84590d21bf0ebd81536037ea06ecf8af46
6eebac17fcf183546a
Output = 049f33c0c8609898143ba60ffd48d4556e7014886cee9b00cd6988408e9
00da1
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5
fcbe
BlindedElement = 030b40be181ffbb3c3ae4a4911287c43261f5e4034781def69c
51608f372a02102
EvaluationElement = 037973b4fa91359b63755fa160518ed1883948b89f051dc4
461228a38920384e23
Output = e9cb8503132fb336395d25c07b36ffe8de4338772dc3254cdf30f9307ec
d65a6
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 4e7804245a743c59d624457677294e04a8bc4bdcd94f0d3bd54f568067489
d34
pkSm = 03b51a0af95c819b09ee80c2056cf0ab0551a5355266d3a0aaff90c3fe915
ed892
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = cee64d86fd20ab4caa264a26c0e3d42fb773b3173ba76f9588c9b14779bd
8d91
BlindedElement = 0222f5dba2da1ec7bd1086d0e04894ef1da1c11163daf376b2b
c76cc51edb16815
EvaluationElement = 0358c726a762c53a80a31f2c27e3e9fbedb6ae3e2435376d
b1f9e568d01e277167
EvaluationProofC = 88d058bdd62214b2c0364b5a38879fd27f700e7b6572aa45d
a6fdc3370721f8f
EvaluationProofS = 1931f6328d5e1d5ccaaafda8b9f38f8ea5310f7f42cdccea6
9e73862921f8635
Output = 1400d402abb54d511199519f6ef30c674fb223a7f1b6cf283dad2dfc4df
8e45a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5c4b401063eff0bf242b4cd534a79bacfc2e715b2db1e7a3ad4ff8af1b24
daa2
BlindedElement = 02f84403d1ceb40a3668349f7c349f806d2c858785853324c66
7505018d13ee160
EvaluationElement = 03fe3f79cfbd77a2a7cb3403f3a3004f87006fa630e41093
3a8079fbe1b5573862
EvaluationProofC = 1d866cd3c431142216061daafc7312876c24c3b70e85fb9a1
d4384eb275a7041
EvaluationProofS = 1ec1d3abc2758ab6756fde220fb1a7e3678c9d587606bbbc9
9f40a131d034133
Output = 9de543d2ea26b8ec400d3b4a460a040497505d9d73ae93e69e8911ea09d
fb3ba
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = f0c7822ba317fb5e86028c44b92bd3aedcf6744d388ca013ef33edd36930
4eda,3b9631be9f8b274d9aaf671bfb6a775229bf435021b89c683259773bc686956
b
BlindedElement = 02a840214a74345570dcadfc927e726901b257b447234fac509
0a1830295ca736c,039a5a8152abb0154b4d79a90486e358ea325980f0bf590524c4
460f700454238f
EvaluationElement = 02773449c06322221199b0b362220492adc0e5f7af976b75
22cce3c881b139aa0a,037ffb2b4730122fdf6857ec1f8fcc847b262dac3c350d633
c8be9398ca2e0ce17
EvaluationProofC = afafbcac6b42f62b4f06ead3d264befd34eb14aa996206aec
7a61754f05a1da5
EvaluationProofS = 57d456f099618498e8d338eb72daa50c1d8755bb03ae83d35
08bc93a6353cc4b
Output = 1400d402abb54d511199519f6ef30c674fb223a7f1b6cf283dad2dfc4df
8e45a,9de543d2ea26b8ec400d3b4a460a040497505d9d73ae93e69e8911ea09dfb3
ba
~~~

## OPRF(P-384, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = ef1b52c12cdf43dc260bf5425a30cde7d708ec34b38dcfbdc2946d7baf525
361e797f6a98f1ebd80f64865f21cde1c6d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0
df382902c13bdc9993d3717bda68fc080b99
BlindedElement = 02fa3115c21ffcacc09ca470729b725781f84333e217cfeec2b
8ba6a54ce492ede7ead3714c5b177427ef853effb1b5c24
EvaluationElement = 03f90418c494c31cda68dfd01e0d53c9c262b76ede26152b
36a17051ca1c4584d78dd34f01745b0075d9daea296f83b3ae
Output = 793e1f56e2047a32c9991d0d846266f06b8e5d3c1d3409c3e77d73ec020
8cec8a106542e3902731bb2779b36ea691e74dd97e7397813ef3180ab2e7ee50cac5
b
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 21ece4f9b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0530b01c
b1c23382c7ec9bdd6e75898e4877d8e2bc17
BlindedElement = 025fddc89a832089a59120df742acb34dba82b26afcae977961
57df238b5905c494a23c56b1f485cbbff78d31df7fa1492
EvaluationElement = 03ca296711d4df53cec5b9d0c27b74a6969fc1253d99f0ee
bbbf56bfa112ddf4c60702fba66b12f13c5c64ca0b10f2f9d3
Output = 5c1782f998bdb0c0192c2e19897f324d8e4612070076dcfd8e23b8e0c52
47e1e0e464c0fd8fc0778e8e38f71b921be0b287e49fcfd0466d41551199bbdb37ce
1
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 67ee1c9e67566d87bfcca9e5dac4bfdb8bdd727c031133fac2aa9ba6c41e6
1e5f8fd401b5d76c7d54b15b15932797479
pkSm = 029b51b2ce9c499f2056e65e0f41d60960f9c4795c0cf94af273ce840c20b
e4cdf87690b6b121b37d399b49afcc2ec9ac3
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09
589e4283efb9cd1ee4061c6bf884e60a8774
BlindedElement = 02a1f41323e91a6ac9fbbb5b8e4c7c58a4c5bcbaa4195557182
cd59e826dc847f1e077de1d402ac92eafe322461fc0d582
EvaluationElement = 02e470adb3907e80edda0c4189a279ca4cc5f53ddb00b43d
f885057f2e7df7c0c69b6e6a0e52113275400392f11be95b90
EvaluationProofC = 70b4602d0fced567d4d8b2954d8ac8ac46dec4824e2f1d69f
513123e5e129013d2f600a6e14fc30558b566e2fa3a1069
EvaluationProofS = 7ad8ed487c1df516c8dec2afa8bce3bf728573ee38246cee5
3de12412fb905fadeff3d87447838a0b847b5a69cde27d3
Output = f8cb7f14fdc14c6ba70cc3474239c33b5d553a177d88e22824ef14b8285
7d6ef6d9f63f1544184a7dcd9d1905108a042f453f129e97da1c1f92bc41d58f55ab
5
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 8aec1d0c3d16afd032da7ba961449a56cec6fb918e932b06d5778ac7f67b
ecfb3e3869237f74106241777f230582e84a
BlindedElement = 02b3465d70f76de3eaf6ecb8080490288f741c622c06d023bd1
80a55a2e3e4eaad08533651f9d278a3f59cec8277780303
EvaluationElement = 03a79023792a4dc15dfe50fff358d1a7e97e59fe3a773ea9
eb78d5161d6e5b3c38773f6e9aeb49685094cba2b8b6d817c4
EvaluationProofC = af0b85019d89edfc00f6b75f86b69dbb3c777491a47c416bb
86fa84d9b9df1224922e701c3d24f513d07a40711cc76c4
EvaluationProofS = ee241aeea0c2f36cbea77f5d04d65ba4c0ff285d538c12827
b82344b9c6fa8a537483f6d7bac403ad4a798d7ebd2e342
Output = 1c42ac047dbf59e4494437d55579965e612681cb4ea38e2197b4e33a545
50322fe828be53c177744c42e6f66b261609241a9209a5638a0d1669559ce045149f
8
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77e
b20c2ae6ba52fe31e13e03bf1d9f39878b23,51171628f1d28bb7402ca4aea6465e2
67b7f977a1fb71593281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf539b
BlindedElement = 02d715dfce1a0724071fa8e530d79f7b234a31739a64166e0fe
21fa6fa0fe19e1ab5e468becca899f31e365c47f3efb2ef,028dfd0c7a38b4cb8477
cae34f041344fb44fc9e55bfa3cf55ab7b4764b74accc7b49c0ff09a524598033dad
1152fb3a1c
EvaluationElement = 033f91d0b29e9867c8a1c3479c3deab5c12c322d5f426a88
55e185f6ef095a95e8abf360195325d396f069ea1289dc29c9,03dee4c9698bb30c7
8b4d3159281c170c13f8cf4acb9d72a8d564350607bbe0831334c668e0a05724f539
93e85f7fdb229
EvaluationProofC = cdd179d51b7810061c652d142ace40787c4ca66c276d4264e
59f2ba64b49be04cccc2a4c84de9b7fe0e13aedd6fb0ff9
EvaluationProofS = 361a2bb4ddc5023282812c00c6524b35c63fb4bba53a46e78
48f90c4dd575d1c1c56fd1bbeb69575232e73d1f059fdf7
Output = f8cb7f14fdc14c6ba70cc3474239c33b5d553a177d88e22824ef14b8285
7d6ef6d9f63f1544184a7dcd9d1905108a042f453f129e97da1c1f92bc41d58f55ab
5,1c42ac047dbf59e4494437d55579965e612681cb4ea38e2197b4e33a54550322fe
828be53c177744c42e6f66b261609241a9209a5638a0d1669559ce045149f8
~~~

## OPRF(P-521, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 016ee706f30ce7e15e4ffa3114c7d59a7b6f302d531ca60419be39d1cd43e
e13b1fc8398b7f63a900cdc49c6e99f65a74403db2fa739927a2ee288cff857d9d84
ecf
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 01b983705fcc9a39607288b935b0797ac6b3c4b2e848823ac9ae16b3a3b5
816be03432370deb7c3c17d9fc7cb4e0ce646e04e42d638e0fa7a434ed340772a8b5
d626
BlindedElement = 0301f0a8c68e58f5571bd39fe3b0b2aa055a8c34e3d68ba0d2e
d177db0bc7575d477ed8f557596feb5ac568fe738eee8cff7dcb56dc78f52bf381c0
912e0e84b5a3f5b
EvaluationElement = 0201b2d9c059393d2a32676b866e473cc9d5d7aafad23f79
1f24aa79145e897cacc75e3f84d1b74e62a314cf5336b1e799a26523b3bb5946e80f
9fc1d2c3e62ab30a23
Output = 0c7e163f494ab681dbac281360607c79fb431a09427417aa5616366121b
cad3857a1c5ba0c85ea298914e60671deaf92de176f5075cede7c8494d5fb1ad5b12
2
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01a03b1096b0316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043b9644c8539857abe3a2022e9c9fd6a1695bbabe8add48bcd149ff3
b841
BlindedElement = 030099c35342a43221c6e03debfb17bad71b62e04c9242aa6e9
f2f915163ef4f5b8b7fe1740a4d636c36bd5c73ca39c69992dc7f6dff8f232125efc
22af4df8352fea2
EvaluationElement = 0301104bc2b5eb0be8b332f96053fb0e59b5fb93dd316c1c
64eda63349ea61a38eee5269664a5a8046a7ca9f08444c09dc06f378079c7af1f118
6b7e7c1a077082a491
Output = 0a02cef4d43b4503457c4b63f67beebc66a92b79542137754db8e26fc70
788947db2b290a74c43f5579d5321fb0f8bb468756273052510a7c997056be21a4ce
f
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 0017674057e06c5e3e8a331f2dc3558540701c9cd0f4c19126d5972af6a01
447b312d05a06dab3e9e07c891d749444c27ede0897ad42aea03b887eb5db93e3f29
a86
pkSm = 0201ee4e2eaa74728f577f4bb282c5440cd454fdee1d79b15a36d34b5e5a1
25e3ccc0f99e32cc0a6a15b5652a0c8a424860c6753f685d0e1e150ceba24ca3386f
29216
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 00bbb82117c88bbd91b8954e16c0b9ceed3ce992b198be1ebfba9ba970db
d75beefbfc6d056b7f7ba1ef79f4facbf2d912c26ce2ecc5bb8d66419b379952e96b
d6f5
BlindedElement = 0200357f949a0a0bdfeb682734dbdeb778f3845045617b21436
27753332e2e75458ab183b12635c75e19afaf56981e7755803026842db1b22fa42c8
61413d07ff86545
EvaluationElement = 020092f7cdbe67f077e439d33e23a38168d7f4431c9b3821
b002a1dc1d31aeaa658edc2f803980819dca422d8a69ef481c94b50a49cdc1472d3b
29775379220aff75ba
EvaluationProofC = 01cc5ab8e66d0fe18bf2f857cc33b8a44f3cdcaf8c5f291f6
0af62030ba0da88ede5ea6c2027db7d0f3822aa5bda0625df25ded354f6c71c01828
10ead28394482e6
EvaluationProofS = 017433d35f05f4db3360a4f9d9c12886eb12638b0c0dd6072
c860107396960d551e10662e55559ffed3acb7508224dd4771b34e1405cec1dd6648
58da1b10856aeab
Output = ae078c627f3313d464517e9f77c3af4f751345ad2392962159ed8bcbfaa
c7a9f8d8538e82a79314265327111bebcd8fdfd36826c5036961faef5bd635c37b2e
1
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 009055c99bf9591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6d688
f70cf205f782fa11a0d61b2f5a8a2a1143368327f3077c68a1545e9aafbba6a90dc0
d40a
BlindedElement = 030185e431f056e75ba7fac49da70790031daa333d16f05e1de
471e24afe0ed985c770ce77bd1bebec527e9a76feecc6afd92c5fd00481ba7fb843d
2aab52337cb716e
EvaluationElement = 03018b6bf8c2aaeee5060f562b698930d2edd07f0fafb8b1
7c20bfbdfe5a4d656aeaff2b8b51daa72bfda2f84e52eccaee80042acbdefd04d3c7
8e3f2d19992213c4ce
EvaluationProofC = 016ffa22bde7a3364c32f7b284d0554cb8c0949aceb1d7035
650ddb068d0756f60a329164cfa696f87d4f3ae987d2e9b2ac4360544cb619e03227
8a8345614c61bf3
EvaluationProofS = 003915d0cd6dbe64fb794b38c2cf520ffdefe2ce8a92443b1
d84227fccedb0cea5bb8d73ba679c1c062754a46ad13151a452fd636415651619a60
81f23e3e05adb32
Output = 7558ced793ee25c1169574ac3c8e788d33c2ba00fd2f0fdf0ccf6475ad1
0390dbcf3ec61cb93f062f28c1da5b85edb117b60387c6efdde6c4b01d3f8a017e91
f
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01c6cf092d80c7cf2cb55388d899515238094c800bdd9c65f71780ba85f5
ae9b4703e17e559ca3ccd1944f9a70536c175f11a827452672b60d4e9f89eba28104
6e29,00cba1ba1a337759061965a423d9d3d6e1e1006dc8984ad28a4c93ecfc36fc2
171046b3c4284855cfa2434ed98db9e68a597db2c14728fade716a6a82d600444b26
e
BlindedElement = 0301978860af75cd69acbc93e8c9fc530e5d2b2208da42c65bf
e079f0f6e0b3fc6080556c10739271d2a8fe578409d4fa9b19ef0484d9c15451c4e7
0501e31da7608cb,0200e30565c3d7e02c822762f25db4c872811adb2cbfbad92b04
291bc8c476d0546d1c5ecf5c58ff06b8d19aad8eca9e5f1a80ff8e981ebc490b0cfb
d5d499b47bad8e
EvaluationElement = 020036d83691e0934477eff706a22c5453c3c0bf369c7476
d391826328c8f6345c4e303df20f9630b29a8fd95abc292713f9867792b6d61163e5
1ee6afff77fc25b10b,03000dbfef7bc24176baca518db912347dd9585282f8ea680
63554b54397db7ce76e7737c148227837efee23f87f907fc2a23d11bc1c9ce4c9118
6a40e9b3bec2f1fab
EvaluationProofC = 014db6d79c00fe3d8f032856af470ce1d63078c2176380902
fdf021bc9be3b5feee48ca0539efe8a3c56606e5b5fc7e5f3bca092f76af2207e217
e664861582d7be0
EvaluationProofS = 01ece82db8ae00a605a6af822de695ab738c7f40e67d1a872
24cdd1453fef9f82818853954a53d86965077512140ab3854b3c9deb4ad0833dae46
d4971153ee4487e
Output = ae078c627f3313d464517e9f77c3af4f751345ad2392962159ed8bcbfaa
c7a9f8d8538e82a79314265327111bebcd8fdfd36826c5036961faef5bd635c37b2e
1,7558ced793ee25c1169574ac3c8e788d33c2ba00fd2f0fdf0ccf6475ad10390dbc
f3ec61cb93f062f28c1da5b85edb117b60387c6efdde6c4b01d3f8a017e91f
~~~

