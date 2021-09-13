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

- "Input": The private client input, an opaque byte string.
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
EvaluationElement = 66ecfab3b267a695078545394308498f66fcdeba1b2748f3
46f9915ed6d49865
Output = 39355cb428aa6b58e03509e419f1cbfd8af85544c24ed530bf83ef66e16
f32ee180c48250cd6dda4f533be4a26c4c6c60278bebb1a3fc6e8a1116d0da242ec7
2
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 483d4f39de5ff77fa0f9a0ad2334dd5bf87f2cda868539d21de
67ce49e7d1536
EvaluationElement = 84c16edc191d5181e0ed85beb66b58cebaba4d14201a84d0
3f6ef37bc6fe8c5e
Output = f8d7e9ef0061eea7426ac7621fec6eeff306060fc712541adca167b85a8
ded3d5e48c7ca585c45677dffa02ac7ff5c6ffcf6ac8d668806f88479fdd97a939ba
e
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
EvaluationElement = a46b311537e6f70ee16f82f76beeff65763d69348efec684
098f692ef8f0cf6a
EvaluationProofC = d2730cc87b235b6941febea71961ed8c62b73721a92669677
67daec1b751600a
EvaluationProofS = 6dfd62d777316055f61ab8b695d3358b33aaea85a8904a39d
e36149130e5c704
Output = 7c78510f5db7fadc51be5598fcc11cb88564091d3daa7f845a6d3df4d97
e129aabb0ca366d389680435b395fd8ef4c2bfc27e6f1ed945d376d2151930b6a62b
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = a86dd4544d0f3ea973926054230767dff16016215f2d73f26d3
f86a81f38cf1a
EvaluationElement = 98e201bb4b0981e0db1bfdf784b066f6738fbfd5b9643d4a
aaf27b08cfaaea2b
EvaluationProofC = eb777f6f0a367208ce6b41376240a84f4ee183673493ba480
70213bbfa31bb09
EvaluationProofS = aec9c123496f4bda364c0ff5f679c8c9a9a707f3a9060f6e2
d205395b7ab0506
Output = 600f72b8b10c3ef600e55e1de4053784abef928d2cda439736b084b91be
153165afa4c7ad33d7d6bfa983b72ae4b535e7cade06248e39a3dec8abe6549629d9
3
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
EvaluationElement = 1e370db5f3b73478bfe4ecd7a1750fb632aab6607b914c5a
74a3b69180a7af55,4ecb25b560ed06eacf0658b8f714bfa3cc7336cc4660c45d8e7
cc64ce847224c
EvaluationProofC = dcf83bde1fbc870af2f0b36b8f77c582418c370ec959b8a59
77d06ea9b2c2304
EvaluationProofS = 64e316f78da9abde67ae344f480a4cb10e0812c26673f1a35
069a83793d7fb01
Output = 7c78510f5db7fadc51be5598fcc11cb88564091d3daa7f845a6d3df4d97
e129aabb0ca366d389680435b395fd8ef4c2bfc27e6f1ed945d376d2151930b6a62b
7,600f72b8b10c3ef600e55e1de4053784abef928d2cda439736b084b91be153165a
fa4c7ad33d7d6bfa983b72ae4b535e7cade06248e39a3dec8abe6549629d93
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
EvaluationElement = e8aa3caecdd4ba11377047bdcf64fb6b545f19817a079bb2
fd59b74e97d8f61b4a50af8b995504b9275a6df7c1c4fd76077ba6fd3ca15f81
Output = 049cfedcfd800bc82b209883e913911871d5feec0eca933a4b7e8f4afef
fadf04f2c5e999d9796bf388907fe4fd212b18ec9255c4fc58b350ffc5099446c0be
0
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = aed1ffa44fd8f0ed16373606a3cf7df589cca86d8ea1abbf5768771dbef3
d401c74ae55ba1e28b9565e1e4018eb261a14134a4ce60c1c718
BlindedElement = 4aa751f84b2634b73efa364b03e60b92b84f457576e6b369eea
b76140e3859d10d2e98174f13f5a2c70670529ccf093d5f1aaf355b4f830b
EvaluationElement = 2c4c4d713ed88e0a523d9c79e077a7b6f95e577bd4c0bb6c
1cbb8e36967b09f1e19cb85644c192e7e0b1d0b130bf3e5f2e21d9e12a3eb626
Output = 422073410cc41b80b3bc1a1f36cc4bbb9dd049f90779379333d99d6448a
a1232a393579dc99af640936ad067fa56a2eb1114da48c58f9a7d304a66d764d8910
c
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
EvaluationElement = 78d888bacc08d7e0b9006d2239853e09a18a29b7dc0d2190
84b275ce8e95964c479c3d5dc18a89df67cdd0a1f672b356028cdbefbb9840c0
EvaluationProofC = 860a1d4fd94568cfee9c18eea5fc578e7ac1d3e65c2e5253a
b988fb752b85f6d09829f37a4c3bf462f3a99eadd0c2aea3c1bee0708e4dd10
EvaluationProofS = 3d6e0d41effda617f9c1d162fa859abd70297b0882a514d0b
03767f34e16d3c6d5d741a9a713ad67956f95dc7b630c697f3a6ece0b08130a
Output = 2976794889d3e015ee0b0733b4eb3dc1d9086b7021a6129abf173107877
35ca0b7a09157a0e8c634cdf04bd579570242aeedcae7a5b2fdeff2db0a9b1642b1a
2
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15b3355179392f40c3d5a15f0d5ffc354e340454ec779f575e4573a3886a
b5e57e4da2985cea9e32f6d95539ce2c7189e1bd7462e8c5483a
BlindedElement = 0e7ddd85c8bc5382e908241c6151afe23a41e0396759b5e38a9
affd996cd822bca242a499793555fc15f07bffdaaa93b42568b307fbdca0f
EvaluationElement = 2649629722508a335d15bcbe72038b789e1493b59f02fadf
730df7459e3cd080e97b025072249496f918eb2ab4233bcf6f67727dccacc18b
EvaluationProofC = 48f4e767bbb65657c6c4c50eb40d2e50dc419acefbaca4d55
3ddace86cbbad9f12856dbb5155e8333edd3af41cf07fc2ace3cfb24546d301
EvaluationProofS = 749b3aef987df338ae4b25eabaa7ec676f12eb7f6b6a79eec
01c61a2880557c224fc475b8e5fe04df9251d465322f16091002f6f6b51461f
Output = c7319781391b720d3e05f7096d961c7e5d812c473fb4cf7262b1ba264bc
ea3c4a58948eb9cb7cf6a6e6393ed02578c0036015dab0a8211fa661264b2d007243
3
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
EvaluationElement = 6ce800c576722d0a4e8beef191d8ecafd309828440e13056
4efaa9af71c63b1870d87c9aff75f34da7b015623f1f8884bf9ea25d5ffa71c2,2a3
6debabdf93bbc27a797af09ac4c64e83bebeb2a7396652bfe301662f358b6f099e91
d69c85087407b2f6a200a5280428447546264b4df
EvaluationProofC = b7351eb6c38248147e572dffa972b31d392aa2498ff4f31be
1d732e1b7dc49eb84710f4e5835006a2a7cb0f9dbce808da538657ef21bd32f
EvaluationProofS = b5bbda03bbc283064b71e84fbe8bc2a6d3f7f9c33d9f32f6e
13569d9b76911fc77877b095eb8c7a08e296b3cb68a420ce1aa0aed3fd1ac25
Output = 2976794889d3e015ee0b0733b4eb3dc1d9086b7021a6129abf173107877
35ca0b7a09157a0e8c634cdf04bd579570242aeedcae7a5b2fdeff2db0a9b1642b1a
2,c7319781391b720d3e05f7096d961c7e5d812c473fb4cf7262b1ba264bcea3c4a5
8948eb9cb7cf6a6e6393ed02578c0036015dab0a8211fa661264b2d0072433
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
EvaluationElement = 038fb89de5efe85a0ceec20c473dadee65a6f21e1727964b
cd4605aeecfdc8fa7f
Output = 01fdba4830d64997a33f4b39ceb64647e9a0ccc670734f95c09fb853d39
1ce76
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5
fcbe
BlindedElement = 030b40be181ffbb3c3ae4a4911287c43261f5e4034781def69c
51608f372a02102
EvaluationElement = 03e4b064e9e5b94a30783cd690b528b6eadc740079b9a153
cfe28cc2b119c19237
Output = e3688c885808a3e227948de755d5c73b89458ccff9f4b4f0fe370bd8eec
6abeb
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
EvaluationElement = 028fd19724b8193244373ff1bfa3385b7fac748e95f25d0b
244615e774cc3c3d34
EvaluationProofC = c827a67c3f4382bcdd59a1a5e6f9fa4fabfe0f836cb53340a
b497eec74057498
EvaluationProofS = 560cfddd591364f354d0d5f643d6f66273f4dfb2adc292fba
818ae4735bca900
Output = f2588d31bcc5c7765e235ca0a22ff27c56ecf6c88d984ff357611832a76
40ab8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5c4b401063eff0bf242b4cd534a79bacfc2e715b2db1e7a3ad4ff8af1b24
daa2
BlindedElement = 02f84403d1ceb40a3668349f7c349f806d2c858785853324c66
7505018d13ee160
EvaluationElement = 0310256b2d99a966f4245e14f824336ae0bf93a2ca0728b8
d939ca31c722afed7c
EvaluationProofC = 095e467238ed7029c6257ccf5fb0625520d9f2342d786386c
ba9d1e6cb575844
EvaluationProofS = da40b39b040dd394133ff6d884ba360bd68a62df0ffac96da
98481f2f67081fd
Output = 53d0d59601ec8b9b9b0ae59dde342c9efb7a318d9a1899c0304ea532b79
8d42a
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
EvaluationElement = 03b71f2db2162ad4b0ce916faa1756b549248bf9f7116834
92853a84b2e9f752aa,020cbd6d0e4080a134d249d40f4cb0cc8cf6e416b32fe0bca
d257f549c0c1cc474
EvaluationProofC = 9cbc218b2f1ec51c29582a061cd5f465e8953f0f048ce5625
1e6af77dd6cab2f
EvaluationProofS = 323d965404abc6aba37302ff6d15d227bb364e437af92d512
8c35054caab1031
Output = f2588d31bcc5c7765e235ca0a22ff27c56ecf6c88d984ff357611832a76
40ab8,53d0d59601ec8b9b9b0ae59dde342c9efb7a318d9a1899c0304ea532b798d4
2a
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
EvaluationElement = 02d83c7c6e80416c0c8d573db48869b9e56b084ba0fb00aa
596c69c43352c5a84e9af7d88d382200dbe1fbf32a0226eec9
Output = 78c53b695ccfba24a9d585cda61bf3eddcc68b75316b630815e5158c1ef
a39816d439d9731f2fa842c4946ca31cb7ae6327d0646190915adc6397421923ba9b
d
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 21ece4f9b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0530b01c
b1c23382c7ec9bdd6e75898e4877d8e2bc17
BlindedElement = 025fddc89a832089a59120df742acb34dba82b26afcae977961
57df238b5905c494a23c56b1f485cbbff78d31df7fa1492
EvaluationElement = 0313035408889860f616245ca790abb82df00c836e9ccebc
e9a70074ee5e1e2acc64d67436126dc50ee0357f9be562096d
Output = 4aacb9e31c490e80eb2cb376d25b705ea536df21f1254f74bddab22a379
02e699eef1f207454ab92056075173b9e51819f170031668e3456ac4ff240daf08ae
9
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
EvaluationElement = 026a871d5d86e3225a041bc4094e05771dbedc347735ec35
155030e568b6d5bc91ad0b4b3ef2515940f77507e348ec31ce
EvaluationProofC = 511ff15c56ffdbd4fc36f31622eb8daf0a10f402cd631c695
93a9b2afa75405b5a609d053970fc615c0d44c813fbd53a
EvaluationProofS = 4ffac38b4ae9ac1b3dc27b12218a4131f7259c830217bb4cd
70dacee83560578c88be0be7e2a7219ae71d88297d29c39
Output = f40fae636aabdea56abb1d206c498e62c1dabda22a31f149c0d15ac3a70
ffa4334c98de84258676d8d5d3a5ba5fcb004d7022a5900c59d1d8f07d85589e1d79
4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 8aec1d0c3d16afd032da7ba961449a56cec6fb918e932b06d5778ac7f67b
ecfb3e3869237f74106241777f230582e84a
BlindedElement = 02b3465d70f76de3eaf6ecb8080490288f741c622c06d023bd1
80a55a2e3e4eaad08533651f9d278a3f59cec8277780303
EvaluationElement = 0394e54a043e0824855484f3d5da4fae881599a7e51f62e8
a49f6328c6e23cac9c78b92e5267f43d20b0ba4ab418599503
EvaluationProofC = aee37a06c3f205d1ffd0c6dabbd4c536c7c2f5256dac672f1
4e275d5412322388b7fb451859f7f3fe3e0e5229e61f481
EvaluationProofS = b0ba0cb025401401598cb247f83bf58358a1479e1221d1a58
a1f3c2d82dd49af6f9c5b082809516955a4e611afe7b2fb
Output = e0b9f7e92926f2879bf2765c62d32feb41414f8e762ff7abd44b081bb3f
445e8c2bed9d0217385740ef00be37fbde78b988557fd10c209171cdb2bb0fe52ce1
1
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
EvaluationElement = 02296d8dd6b4fa3c85478c371410d4729a9a309e7ca9c19b
0bf033f6b2c57e2b92b9e719a25932096d98dc202db84841bd,02233f79a9b8851c0
7bf8928d86a8934a421a3d69687dff394ddd00d943dd49addc289ed272cb645475d0
09909cfaf17e7
EvaluationProofC = 14931a6b883296ce8d8c403b15b8a9a0a89890affe38cc629
3a334f5067350fa30dd026aaa00247c1ec50420d6f1f25f
EvaluationProofS = 5b81be1467b8e03540ec5fbc2f58bf6856f8ae3c1fd40e293
23adf3a00627cb6615b91c521686e8a0c653b13f56cbb5b
Output = f40fae636aabdea56abb1d206c498e62c1dabda22a31f149c0d15ac3a70
ffa4334c98de84258676d8d5d3a5ba5fcb004d7022a5900c59d1d8f07d85589e1d79
4,e0b9f7e92926f2879bf2765c62d32feb41414f8e762ff7abd44b081bb3f445e8c2
bed9d0217385740ef00be37fbde78b988557fd10c209171cdb2bb0fe52ce11
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
EvaluationElement = 0300cc374528a7765eff72ccdaaf915a317c4463ac06f558
66d277e095403f9d37f382f086b423dcb0dcec0448a2060f8d6857bacf35d1037b08
9d6d8670aea7858c1f
Output = 0e1f6c889e5ececaa1bbaef0be1d1c48c73797fc012cefbca97bf3b5987
49958e681c757adc776faef3d262251e016d288d5180ff771939f40e1eea80072a10
b
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
EvaluationElement = 0300433cf2b72d57a881cd3e6a5842f7a8e18b9121da962e
7659f1eac5941661a4852e81e0b226c7b00d7f9aed87ab960277660ffcb862c87e25
9ac2a104e4052da848
Output = f00721296d290c684a11b1ab2b407139defc3a983e0b7a37bb3ddf0f6d8
b1d103f3dfc211ecbe7f341a82c1bf6f80cc9c9b9b7b1f672fd9ff4074386c577a8b
3
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
EvaluationElement = 0201c93f65da0d5338ac28f28259dd6914e75f57c9622859
6cfa5e02009a02e4c523d19b926900f250540e371935be550c9b111de8d83ee06fe0
f6ba987f3f4a9b71a0
EvaluationProofC = 0099059a58d6b1bcd0581d85b8bfc39d3eb2a0e57911fb59f
4926d61a08cd245c44545f5c7bb2ff9805cd673c57a5877a3d45fded1989f0be9f7c
54a986a95f05ac8
EvaluationProofS = 010e7f4e372aef67378e3336dec6db28ceb5ca8d86dd7f288
6dd7a9f197ef6ed56ae15f65e063f79a61a666f90b6695cde184bc6d24841016d0e8
0691ef28e093744
Output = 542230ea7ad311974fe9b9c659799bafec7e57824826f3423d8ee3a983a
9d914562703a2a72675a406ade976793fcc28676340101c5a4e9efef57a299a3bd28
2
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
EvaluationElement = 03002348a9c6fdf6652ac9f60c2184f98a3cb8072f61e437
0bd2179e16c9c6dc3a603e13c1da64f9a865e97eb25ee7acfbc94da87e937465b8d6
3ae93b2b064e97689a
EvaluationProofC = 00920a2597a5fb4c777a0979bdeca58208cebd3852dcde58a
4580fa82ce8bf59ef4977ad276662c546c9859d4d1767bb6a55df925cd0e7a7c3a91
322f3d5f5825626
EvaluationProofS = 01db5cb2c59c6cec43ffd0a07e268930fc39b166201a98f12
9ce374ed4c33854fe358fda4666080c54b67e3313699249b2996ab59e6cdb32b644d
a084500c0f13a13
Output = 711ed2f4540466d9546b8d3a48f5c63394888ebfcd3c3c08dc6ccf617e9
053661615970c9f99fd825003b9c49aaa56a851fe4e1fd2b6bc6e7d778372ec3fd64
0
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
EvaluationElement = 0300f7b042ea181fc79f180dafc87404537f14509ba87023
ba0935762239c37e4b204747e8d7ee279dc2deda1b0c6e06fcf72f4d94dae8dc7b96
9d395455e550d2cec7,0300528d00a98ad95939176afe9487140d64bcd84b9b18216
a73a515477f0f983711ec8f02dec1363c080e347c8e02cf094fd9e526b013ed5efbc
9e508258a116197d7
EvaluationProofC = 011b960cef0e64db0d0ab92d77c0c89c8d7d0f0fdf18dc46d
b139ae3a61b5378f6dac6468c36ef4122ba6c5f4c4b90156f7453701a72c1c380e27
401fad0b273173d
EvaluationProofS = 0019308b2379533796dd01d9f26c8ec71f007180837596536
40e6e67e5752302618955a3d35e1ef2a096b3018228b74312611c9552649352f7be2
d0770f6f51c3414
Output = 542230ea7ad311974fe9b9c659799bafec7e57824826f3423d8ee3a983a
9d914562703a2a72675a406ade976793fcc28676340101c5a4e9efef57a299a3bd28
2,711ed2f4540466d9546b8d3a48f5c63394888ebfcd3c3c08dc6ccf617e90536616
15970c9f99fd825003b9c49aaa56a851fe4e1fd2b6bc6e7d778372ec3fd640
~~~
