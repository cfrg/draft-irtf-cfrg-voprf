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
private key, and the other (the client) holds the PRF input. The
'obliviousness' property ensures that the server does not learn anything
about the client's input during the evaluation. The client should also
not learn anything about the server's private PRF key. Optionally, OPRFs
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
a known public key that serves as a commitment to the server's private
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
- Server: Computes the pseudorandom function over a private key. Learns
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
the protocol runs to compute `output = F(skS, input, info)` as follows:

~~~
    Client(input, info)                               Server(skS, info)
  ----------------------------------------------------------------------
    blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

                 evaluatedElement = Evaluate(skS, blindedElement, info)

                             evaluatedElement
                               <----------

    output = Finalize(input, blind, evaluatedElement, blindedElement, info)
~~~

In `Blind` the client generates a blinded element and blinding data. The server
computes the (V)OPRF evaluation in `Evaluate` over the client's blinded element,
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
            I2OSP(len(info), 2) || info
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

## OPRF(P-384, SHA-384)

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

# Acknowledgements

This document resulted from the work of the Privacy Pass team
{{PrivacyPass}}. The authors would also like to acknowledge helpful
conversations with Hugo Krawczyk. Eli-Shaoul Khedouri provided
additional review and comments on key consistency. Daniel Bourdrez,
Tatiana Bradley, Sofia Celi, Frank Denis, Kevin Lewi, and Bas Westerbaan
also provided helpful input and contributions to the document.

--- back

# Test Vectors

This section includes test vectors for the (V)OPRF protocol specified
in this document. For each ciphersuite specified in {{ciphersuites}},
there is a set of test vectors for the protocol when run in the base
mode and verifiable mode. Each test vector lists the batch size for
the evaluation. Each test vector value is encoded as a hexadecimal
byte string. The label for each test vector value is described below.

- "Input": The private client input, an opaque byte string.
- "Info": The public info, an opaque byte string.
- "Blind": The blind value output by `Blind()`, a serialized `Scalar`
  of `Ns` bytes long.
- "BlindedElement": The blinded value output by `Blind()`, a serialized
  `Element` of `Ne` bytes long.
- "EvaluatedElement": The evaluated element output by `Evaluate()`,
  a serialized `Element` of `Ne` bytes long.
- "Proof": The serialized `Proof` output from `GenerateProof()` (only
  listed for verifiable mode test vectors), composed of two serialized
  `Scalar` values each of `Ns` bytes long.
- "ProofRandomScalar": The random scalar `r` computed in `GenerateProof()`
  (only listed for verifiable mode test vectors), a serialized `Scalar` of
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
EvaluationElement = 922e4c04b9f3b3e795d322a306c0ab9d96b667df9b949c05
2c8c75435a9dbf2f
Output = 9e857d0e8523b8eb9e995d455ae6ae19f75d85ac8b5df62c50616fb5aa0
ced3da5646698089c36dead28f9ad8e489fc0ee1c8e168725c38ed50f3783a5c520c
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 483d4f39de5ff77fa0f9a0ad2334dd5bf87f2cda868539d21de
67ce49e7d1536
EvaluationElement = 6eef6ee53c6fb17c77ae47e78bdca2e1094f98785e7b9a14
f09be20797dad656
Output = b090b2ff80028771c14fecf2f37c1b14e46deec59c83d3b943c51d315bd
3bf7d32c399ed0c4ce6003339ab9ed4ad168bfb595e43530c9d73ff02ab0f1263d93
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
EvaluationElement = f8a50ed35a477b0cde91d926e1bc5ae59b97d5bd0dda51a7
28b0f036ec557d79
Proof = 7a5375eb1dbad259431f5c294e816a1c1483c279748da1a75d91f8a81438
ea08355d4087d4d848b46878dcc8fb5849ac7a09133382c2c6129564a7f7b4b7bf01
ProofRandomScalar = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9d
bcec831b8c681a09
Output = 4b2ff4c984985829c3cd9d90c255cdc0d6b61c4c0aafa9215769d51cf7d
eb01472ba945928a8305e010f12b7dcc75a9dc2460439e6297d57dc2ce7ca0abaae1
a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = a86dd4544d0f3ea973926054230767dff16016215f2d73f26d3
f86a81f38cf1a
EvaluationElement = 9e47810f1de1b57ebe163a95c170ec165a2063f872155c37
6d94e8de2157af70
Proof = 61075125d851d5164b0aa1a4d5ddeebaf097266450ac6019579af5f7abd1
90088eb0f6f1e7f9d8bfddbc21ae3c25a065e6c4e797d15f345ed4fb9ee468d24c0a
ProofRandomScalar = 74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df
9d013f7d6c312a0b
Output = fe1fb7fa49c37dc7cd31d64859b4a2e6ae0cef294f2764e6f12f7d809f2
18047d1fde147cf69807b8971fb2c316eb572be2b5bf491813bfec0a20668d6d07b0
b
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
EvaluationElement = 3afe48eab00493eb1b073e95f57a456cde9aefe463dd1e6d
0144bf6e99ce411c,daaf9421318fd2c7fcdf369cb348748cf4dd177cce30ee4d13c
eb1644b85b653
Proof = 601381ecbe127ada04c057b8b1fc21d912f71e49252780dd0d0ac768b233
ce035f9b489a994c1d14b92d603ebcffee4f5cfadc953f69bb62648c6e662613ae00
ProofRandomScalar = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186
a9706137886dce08
Output = 4b2ff4c984985829c3cd9d90c255cdc0d6b61c4c0aafa9215769d51cf7d
eb01472ba945928a8305e010f12b7dcc75a9dc2460439e6297d57dc2ce7ca0abaae1
a,fe1fb7fa49c37dc7cd31d64859b4a2e6ae0cef294f2764e6f12f7d809f218047d1
fde147cf69807b8971fb2c316eb572be2b5bf491813bfec0a20668d6d07b0b
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
EvaluationElement = de477252a5ff3c7d51ce159cb8ccf1865d8c7d3402824163
8d80971f13a59d87b2b1036341b98089555ab088278391794c49bbb052fdbcff
Output = df8f910c3b84d1f3ca6afd1992768608a20f2ad7b770e9d89d303c88ba1
5bb7d991f2f7ffd5b5b51fa3bcf8fa06779609497f6c0ae4e9cb2dcd48c68b4ac6b9
4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = aed1ffa44fd8f0ed16373606a3cf7df589cca86d8ea1abbf5768771dbef3
d401c74ae55ba1e28b9565e1e4018eb261a14134a4ce60c1c718
BlindedElement = 4aa751f84b2634b73efa364b03e60b92b84f457576e6b369eea
b76140e3859d10d2e98174f13f5a2c70670529ccf093d5f1aaf355b4f830b
EvaluationElement = 085ea1cb452a2fb15b3a0d0e1c86899c7ea49fe2e4856ef4
f95bc2542eec610fc09b0fe7d7ed7389d86af6a646695b7ad46527dc2a936aa4
Output = b57516a737879ece1110ad5d051ac0a6c54e1dcd989c907721ecebab5b4
5877cc693c3c05d0bd416c5a9ceba36de41a0a31679c146fe4c110c64b056eba1720
b
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
EvaluationElement = d29849d8ad1e651328e8119003debd9ecd54cc786a5eb8ae
ea56487ffc09120e98792f9475605488d16623b8e3cfa5af1ec27e76bc841b75
Proof = 8b3b8f0c9eb22527e419f5a03d4d3f34cf725837424a38c5b4f88c7759f7
a54bade57b7930bfeff051be9bfeaabc8976ed407398e0ce462a062e068a8d57bc1c
411bc42fe714626cfb92ad854a56636c2b83f2b5215c2ff531b22e4d37031523db20
3556959e275b46b84303ed23fc37
ProofRandomScalar = 1b3f5a55b2f18f8c53d4ecf2e1c27e1028f1c345bb504486
4aa9dd8439d7520a7ba6183d50ef08bdf6c781aa465660c93e8195a8d231b62f
Output = 1ff5c5c2c081c76006b52c45f79728882dc48962036ea7d4d5097b04e93
9ae81118a7fe5f0a66a6131bef18b9cd998150f10c62619ec4c2d223ea57dc67f153
d
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15b3355179392f40c3d5a15f0d5ffc354e340454ec779f575e4573a3886a
b5e57e4da2985cea9e32f6d95539ce2c7189e1bd7462e8c5483a
BlindedElement = 0e7ddd85c8bc5382e908241c6151afe23a41e0396759b5e38a9
affd996cd822bca242a499793555fc15f07bffdaaa93b42568b307fbdca0f
EvaluationElement = 4c81e29e8a9502fa02e00cb09cf40d9b98988ac9b4bce7cc
a0656caeb0926b59c7000d7fe6c5dd814f831864547d2360d223a50077bd04fe
Proof = 74fc8fbf2e669dc5d25898ea8ce45d1d3eb97edb4b7c3cee39865a3c66da
6b7bad4ad3e77794d6f5e82fa8a645b9b973a8612bfcd1194302f700ee3433e876d8
3f96bb70f19ff292605ad4c9466fd71dbc2ed22ade0130574e5ee343ef45d42e834a
11a19fd6f5b1b5ef910bcccf731b
ProofRandomScalar = 2f2e9955be83a4b25743ebd3618d4fad8b7288477da50bed
9befa58af639ddd950fec34205f8a4f166fadcb8fa71a3ffdd2e98f4c8ef5e26
Output = 2753e222528f1ee5fcc6ad4bf1ca953e5d3b47c1dfae85710f46a0a030c
07f59055e9b05dacb729a7ce41cd2ed782f8a76a1b3f74b40196aed0b6938b89c60f
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
EvaluationElement = 8a0d34fdb0b55121421546ff952c7bd3cbe469926ff9ad4f
aeba243823955529eeae4f1a7a64cd055ec01baa041a99dfbe1a67ca4d59f93d,5e8
6e0b41cc88186ee0003baa46535e71acd98453b298976b92be2cca2646e88620f55d
f6bf4754456dfd8d84f6889c17b5ff93052325a1a
Proof = 1ff624a102b99771c76a9414e9b3f33127897d971bc84a922e464805e4a9
f27b889922030adebbbd58e0ab618ade9c84bfe8aa226176f11f432958ea1e6f6926
3aef51db9efb23ee504d233c17e9077c0373401da167637a1df4eafd9c2537c9f89c
103f9e635931fe2042419dd9bd37
ProofRandomScalar = a614f1894bcf6a1c7cef33909b794fe6e69a642b20f4c911
8febffaf6b6a31471fe7794aa77ced123f07e56cc27de60b0ab106c0b8eab127
Output = 1ff5c5c2c081c76006b52c45f79728882dc48962036ea7d4d5097b04e93
9ae81118a7fe5f0a66a6131bef18b9cd998150f10c62619ec4c2d223ea57dc67f153
d,2753e222528f1ee5fcc6ad4bf1ca953e5d3b47c1dfae85710f46a0a030c07f5905
5e9b05dacb729a7ce41cd2ed782f8a76a1b3f74b40196aed0b6938b89c60f9
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
BlindedElement = 02229d3cf55e084812821c3ee8124e72c36f17caa7cfa3f3bed
6aae05be73f7bb9
EvaluationElement = 03d0d69568273dffa70597bbbffc8ceae096e22c1abbfb62
b15c380125de1defe1
Output = 5cea5d9f7ee102362471eb175b2f10f7bc755cba1a6fa46bf45276b07ff
48482
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5
fcbe
BlindedElement = 032a195fc752279a1dac1df2da50229b6da1d90621f2eecc04c
45d9b3cf532c92a
EvaluationElement = 03d00cbd2a0daa0507efaddf6d254d3efc9bf0aa64aa3f3e
1c5f8246fae0e545d3
Output = cccc1971f5a6974e8f418a9a78aa3285bb10355dc1a5e8c48f427cfb710
63394
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
BlindedElement = 03b86fa26a39472dba928d2d946e71bbd389204ceda60b365d4
27976ccbab3af32
EvaluationElement = 02bb810d5928918833f907f75274e6a42e821f6d11950c07
59145585c665879a23
Proof = f952165afad9ac3429eff7e2130a96f80689415be8051e1caef83933db53
cd7e4f489fb38d96d77ab3f2d251b4fa0f0bbcf17e9087872f80db41394eb30a5d9e
ProofRandomScalar = 70a5204b2b606f5a28328916e1e5ea5a17862d7a261fdd6d
959759758d5e34ac
Output = 1c7fd49f1e91cc112f8854012776afb264d119b950301ad89b44678637d
776eb
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5c4b401063eff0bf242b4cd534a79bacfc2e715b2db1e7a3ad4ff8af1b24
daa2
BlindedElement = 03d48a789c1e641f7489f16eb05e2363874101a77c5410ce5e2
3f39484555e625b
EvaluationElement = 02a69e4334b64b725275f448b671db69880d665499e4f34a
830fd2b0955751f669
Proof = a4b32d18c106cfb4a895ede4adaeefffa3237409a9766a59766eb3196935
def86cbd4acbc737aff41c71a26e0e26197273bb76d8e17c4a3523bf10ce93228e63
ProofRandomScalar = 3b9217801b5d51cef66d9fdbd94a53533e7c5057e09e2200
65ea8c257c0dd606
Output = a79e5aeb667d20734cbb9235991e4c7049fc225a35847fb01acf31b4ef8
b714e
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = f0c7822ba317fb5e86028c44b92bd3aedcf6744d388ca013ef33edd36930
4eda,3b9631be9f8b274d9aaf671bfb6a775229bf435021b89c683259773bc686956
b
BlindedElement = 02bab6dd5885e996b89ae1c846c65cd1b2cf15477bac2fd3b62
5fd36d05b3b3f92,0374f008c8230bd3cf53ce5e267a53e8315acdd3f5434055a201
e578dd9296e4d7
EvaluationElement = 0300aab295bb7cd0aaffb7577a0805ddda2dab99b384f596
78b7fc3d7cf1160576,02234c5d871665f9f29ec9bfe47340ca97edca83877ca8fc3
ff9938c84e1974a4d
Proof = 245249c1bdabd8af6e17a6ec6c0de2ac9d4c9b53d31739de5441bf207b01
c60f6cec5a1a6a79349c0cc82be6137a927c8b8688ecc5922599a753a445c869b15a
ProofRandomScalar = 8306b863276ae74049615162a416d507a6532c99c1ea3f03
d05f6e78dc1edabe
Output = 1c7fd49f1e91cc112f8854012776afb264d119b950301ad89b44678637d
776eb,a79e5aeb667d20734cbb9235991e4c7049fc225a35847fb01acf31b4ef8b71
4e
~~~

## OPRF(P-384, SHA-384)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 1a567f3adf7628e41de9edcbb42ed184fd6432ae6add63fc89f50dd7d5fd4
cf48e36c7764d32a67639bfcd796b025919
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0
df382902c13bdc9993d3717bda68fc080b99
BlindedElement = 032b2628f247fe80b6b20fc773ad586f4f9083c1c3a031a0ac5
a5418c0b905377df3fa2d49da7673f4dd8670dc20549fc4
EvaluationElement = 02549e75e2fc40be2893295e6048dc7bc007f04928ca65c5
a925a29cc3686d39c4a184468a167437f39e206f3d3c0e7eff
Output = 8a7597cbe645fc06aae24a53a3061ea38fe9364293406bb78e6b9dd90d0
d8df724f32716874c49350b7cc632f640b97a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 21ece4f9b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0530b01c
b1c23382c7ec9bdd6e75898e4877d8e2bc17
BlindedElement = 03e4b6ff47863d4ec62a9e6562645448b4f91bef176c3330947
b1016ef275118671967ea95183cede2336a3b08c87b943e
EvaluationElement = 0249832e49167531b30a6984474917bbc9b436b0a2e5bcc2
d9878182bfa13d253375dbd1cf19b2cece3cf1c2ce4e32e8ba
Output = b9f81f031c67070038cee6e51a94c004f64953766e2e5c042b34fae4984
be71273acb1aa27c0a42b6b634538ace890f4
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 95c660e15a645395841c6107b176526a844fc6582004a00175adb509f31bd
378ea8c173d07917aa3661496be8fc188cf
pkSm = 032e820b6dcb36cd07afa12a8c3b96787efcc5dfabc6dfda3883e943f8903
9d972181c13ab4b9d574da1ab49177f1a253c
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09
589e4283efb9cd1ee4061c6bf884e60a8774
BlindedElement = 0302cc1ce7487c5af4d5fc5ffedb0972e847db3a82510dcd272
9cc25ead264472e138a58aa320b671a80224d04403958da
EvaluationElement = 0255ceea5fce011096bb3a18c33e032de7f21a3551abc84d
579e14113304356577c806df5935ac45760000fc8e700b2d7c
Proof = 5e60bdbd4093614c1ff1a12cb4d946079850b28d811e38ada9bf87801259
2a711f4408cebb9e39f05d1191627e35362253adc2181383be7d17b759418d1eb623
d75ecca415e05f1ab1f42324c21b60b2cff20ae88502a026d2740a4b5531a136
ProofRandomScalar = 90f67cafc0ffaa7a1e1d1ced3c477fea691e696032c8709c
86cbcda2b184ad0029d29abeabede9788d11782429bff297
Output = faa6c0c080b97c6a67ced85f0327ce253147c48589e060b862d4849fb94
0f73273c06654d7dad38ed2b3b4180eb81785
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 8aec1d0c3d16afd032da7ba961449a56cec6fb918e932b06d5778ac7f67b
ecfb3e3869237f74106241777f230582e84a
BlindedElement = 024b70115d9579e00d1c1a5c82e5618c383e9deea24e41baf53
40d04436172c2931e8d657b90649b8aa3e09782162581ff
EvaluationElement = 03b7a1d6dadcfe7bf9483f85128c38c0eb8cae2829efc0b0
e32d9127ffc1fe6e39faaffc903006e673c7713b795927534b
Proof = 4354ea60fad06417f3880a38204e1122e44680ca4f1f66032ab68cb68e34
59f476c4feced80761edf08f30e3bdbcab2ec6e1b34d6f1cccbe1c871e32845e4df3
1bc15fc9aabb87fb4a57646a5d1a92a41c5bbd4b8d2240cdc66f92c09e583c02
ProofRandomScalar = bb1876a7f7165ac7ec79bfd5213ea2e374252f29a6e19915
f81b0c7dcea93ce6580e089ede31c1b6b5b33494581b4868
Output = bf6c6463b0fbd20a17e12779736973f16e1bf3c10be1f6415a1786bdb42
742dfa8a33770973cec5a26d0abd984c4214a
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77e
b20c2ae6ba52fe31e13e03bf1d9f39878b23,51171628f1d28bb7402ca4aea6465e2
67b7f977a1fb71593281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf539b
BlindedElement = 02494b5c3bb1dbf7db95d47bc051a9285581b2c8d9c67965808
e8e7af48bebc138444d0d23bb0c1cc15aa343d842ad3ff4,02b90fba828dc450038f
8ab1ad5e1a32eac158d7340168018d9be4ad5f8b125bc82ab45949ca4d389668d0f0
59ee20e320
EvaluationElement = 031e2585f42f67e0248d7bd484693d89f1a2145a04912963
2458658dbf75bea4854ce30e3359c26b6b79742a5eb402fbd5,02eb63b059f5e036d
ec973901962e0b111a8208d690760577bff897c25ad80ed5077e03df3fdb197d5d10
c5715f4475645
Proof = 127f1843af2867d960b6c1136e81f47a280746b081ffe1d1e403e7685eae
7b31b396bdf7c2e74f5c913692927d982a3fb8447dcc0da025666464380239853d02
1c554c52dd098bc3e575cdbcd1f88000c282d1627c2d1d5e1e18141c1ce7b768
ProofRandomScalar = 1b538ff23749be19e92df82df1acd3f606cc9faa9dc7ab25
1997738a3a232f352c2059c25684e6ccea420f8d0c793fa0
Output = faa6c0c080b97c6a67ced85f0327ce253147c48589e060b862d4849fb94
0f73273c06654d7dad38ed2b3b4180eb81785,bf6c6463b0fbd20a17e12779736973
f16e1bf3c10be1f6415a1786bdb42742dfa8a33770973cec5a26d0abd984c4214a
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
BlindedElement = 03019d5b91b7e245c573082f0a865a19aaeb0809c60cb2b152f
c3ebcee5a053fce0429b60d78600d7314ff67a040f283d3828c6bca36b2daab40917
257643459f7be10
EvaluationElement = 020036ce135c8a41b705a114ffff15341fa44aebb80aba6a
1cb9d14c86b2043b031df316435519badf7324254540437d9497fe86dfedb965349b
56b7f1328698add70e
Output = 38788af282b3fdf1858b8b8650db18bddf946ec981f0323762584337979
7a5cc2803154819b245c4f1cca6e926415285a189ce1b71da42567196c2517e54ac5
4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01a03b1096b0316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043b9644c8539857abe3a2022e9c9fd6a1695bbabe8add48bcd149ff3
b841
BlindedElement = 0200cc6f72ec7d21bd8052318daa0b6c8dfe0a7bb61678d52ba
a111f6c3830043f29b07d94b5a5863a3dd75d97287ff91be183c76f1c5bdfca39304
c774b07c3c10619
EvaluationElement = 0201225cc14d504dcc13f388f687f225daab97179ac07cc0
697827521e6feddf36126bbd822a877147c90c0aa02b51f6d80f68fcd033dd78c092
e3cc7273413265f206
Output = 6fa9f6ef0c2183c5a74c4c6ee2eced2004565d1462af5044b74871d47d8
6680cdb32e96022a34673c3bda3ac15d103d2b1adcabe1cdbe86647ef774425e03b6
b
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
BlindedElement = 030032990a878f1dbb27c123fb984afe025748b89f17da74a5b
d3811bea502da14ed8674d6e9423f05e7d599e6eeaa3d22bd632e6521d2ce91d9428
d497e90bee4f12a
EvaluationElement = 0201f865fc64e676a214f705ba494c1a827d8a8a6ef7563f
fc633a4b24168f191b4f940bbfd082b781146f8e084faa06d1418a44ee366a3a6318
bcea25e36943f2de63
Proof = 00b1a60738f1d8af85c94bb45afccb6cdf0abd26959081eda45869e1316f
1e9bf3a7b763d93cc96df6dddc35740a8b558cbd0adaaaaa313e84a2127c3e892d03
a30700272e8dec114c08caafb31a1c24ead38ea4f511237f3914baeb1efa14a6e660
8703d95b9603e0afd26182b6ec7063d0625de369d8e28703797eb4320f32fb42ccd9
ProofRandomScalar = 00ce4f0d824939827888f4c28773466f3c0a05741260040b
c9f302a4fea13f1d8f2f6b92a02a32d5eb06f81de7960470f06169bee12cf47965b7
2a59946ca3879670
Output = 95f902b748533f52faafd1e85947877a4565c21f6fd9f126d7e65db7072
9f6b92ac6e2c62a4c12d10064ed993b2f67d889ce7664c9d37954b4aa63851802332
f
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 009055c99bf9591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6d688
f70cf205f782fa11a0d61b2f5a8a2a1143368327f3077c68a1545e9aafbba6a90dc0
d40a
BlindedElement = 03013ba0f409a9a4d095e6669ec128366bee037ed24bfc7d6ae
16b4acb8c6f32dfb8d4a5841b2d67bfcb47cac8dd056b90844cd782b4d7e6b039920
320195a8aee698f
EvaluationElement = 030071c49fd511fa62dfb1a83bc622389cb9f9d843d71512
a98094ea8f0dbab40059bda485afcfdd652096cd0f4d7246bf738e5c94f1e34682d7
eea370e1c03cb52a3f
Proof = 003701210331c8efe8e2824e5d0cefe2e13e462f6d4061b4f1ddd02460a0
c54d3adb63f25aef50a4f24597752eec0ce7ca844ee29d294595a903da770b9fccd3
8616013661158b84e448dfea7ae1eb89ab8824d686f0e456668c3e9c8538d3ce0f02
098f0e9085bf1effdaf93b04f2aa52791acf2a686ea55d92eee926255323c37e407c
ProofRandomScalar = 00b5dfc19eb96faba6382ec845097904db87240b9dd47b1e
487ec625f11a7ba2cc3de74c5078a81806f74dd65065273c5bd886c7f87ff8c5f39f
90320718eff747e3
Output = 7c5bc402a6c0f5c62efae91c99833c24f2d66eb4a49af021dfbccc94d0c
0eb315250265827d2876ba7a06de76f5e949a68714dbc6ead3598849e645d22c1591
8
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
BlindedElement = 03003c1ac76702df08da5ae8ac78d5839e6c540fc5e08fb8fbb
5b51df7cd631756d2f0e67c0db6edede0492a14e34359daf0277a92652ac2f6d7616
9c35dbcc1d1dd05,03015aa2f736c3dfbdbc0744474f1bba52f103313e01631b57f1
5f6706d9a81d87c1366b4dec67b771cc47e53fc8f81549a42c4fd41414362aa95397
442955b16ec9d9
EvaluationElement = 0300121cfdbd6482165b777e98a06feda3b400fc7a05a4a7
de0c7f7cde7cbc091a23f0e440627974b791307ba36bf621abe37dcb8f503fcceb9f
b1fbb995903b5c08ce,03012aca7d5df208b38e3199ae6f8527ef724dfdfa38ec532
54f2662799ad4f48fb91873dd4ac0c0b9a373375e82f59cb0f181bfca0a3c99dfb19
2c8e1890dd7e01e21
Proof = 00cae68666860dfdeb710095068f4c6e5b4240a35d92d96149406aeceb2c
d18fe231c6864218e7e530152bfe65b6d04d95dbbc5b6cb6137330b96ac632d5e315
0f1b016b1b6691da11c27708dffdcd10b8520ce42ae153f4d8fae3b591c94e6cea67
a0391af9974abca24b9058b3f8c6b3dff9a38e25c14ec66baa68e87fe922611e523a
ProofRandomScalar = 00d47b0d4ca4c64825ba085de242042b84d9ebe3b2e9de07
678ff96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd1fa76e953a630772f68b
53baade9962d1646
Output = 95f902b748533f52faafd1e85947877a4565c21f6fd9f126d7e65db7072
9f6b92ac6e2c62a4c12d10064ed993b2f67d889ce7664c9d37954b4aa63851802332
f,7c5bc402a6c0f5c62efae91c99833c24f2d66eb4a49af021dfbccc94d0c0eb3152
50265827d2876ba7a06de76f5e949a68714dbc6ead3598849e645d22c15918
~~~
