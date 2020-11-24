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
    org: Cloudflare
    street: County Hall
    city: London, SE1 7GP
    country: United Kingdom
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
    target: https://www.secg.org/sec1-v2.pdff
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

--- abstract

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol for
computing the output of a PRF. One party (the server) holds the PRF
secret key, and the other (the client) holds the PRF input. The
'obliviousness' property ensures that the server does not learn anything
about the client's input during the evaluation. The client should also
not learn anything about the server's secret PRF key. Optionally, OPRFs
can also satisfy a notion 'verifiability' (VOPRF). In this setting, the
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

## Change log

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

- Certify public key during VerifiableFinalize
- Remove protocol integration advice
- Add text discussing how to perform domain separation
- Drop OPRF_/VOPRF_ prefix from algorithm names
- Make prime-order group assumption explicit
- Changes to algorithms accepting batched inputs
- Changes to construction of batched DLEQ proofs
- Updated ciphersuites to be consistent with hash-to-curve and added
  OPRF specific ciphersuites

[draft-02](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-02):

- Added section discussing cryptographic security and static DH oracles
- Updated batched proof algorithms

[draft-01](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-01):

- Updated ciphersuites to be in line with
  https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04
- Made some necessary modular reductions more explicit

## Terminology {#terminology}

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

## Prime-order group API {#pog}

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
element A with itself `r-1` times, this is denoted as `r*A = A + ... +
A`. For any element `A`, the equality `p*A=I` holds. Scalar base multiplication
is equivalent to the repeated application of the group operation on the
base point with itself `r-1` times, this is denoted as `ScalarBaseMult(r)`.
The set of scalars corresponds to `GF(p)`.

We now detail a number of member functions that can be invoked on a
prime-order group.

- Order(): Outputs the order of GG (i.e. `p`).
- Identity(): Outputs the identity element of the group (i.e. `I`).
- SerializeElement(A): A member function of `GG` that maps a group element `A`
  to a unique byte array `buf` of fixed length `Ne`.
- DeserializeElement(buf): A member function of `GG` that maps a byte array
  `buf` to a group element `A`, or fails if the input is not a valid
  byte representation of an element.
- SerializeScalar(s): A member function of `GG` that maps a scalar element `s`
  to a unique byte array `buf` of fixed length `Ns`.
- DeserializeScalar(buf): A member function of `GG` that maps a byte array
  `buf` to a scalar `s`, or fails if the input is not a valid byte
  representation of a scalar.
- HashToGroup(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to an element of `GG`. The map must ensure that,
  for any adversary receiving `R = HashToGroup(x)`, it is
  computationally difficult to reverse the mapping. Examples of hash to
  group functions satisfying this property are described for prime-order
  (sub)groups of elliptic curves, see {{!I-D.irtf-cfrg-hash-to-curve}}.
- HashToScalar(x): A member function of `GG` that deterministically maps
  an array of bytes `x` to an element in GF(p). A recommended method
  for its implementation is instantiating the hash to field function,
  defined in {{!I-D.irtf-cfrg-hash-to-curve}} setting the target field to GF(p).
- RandomScalar(): A member function of `GG` that chooses at random a
  non-zero element in GF(p).

It is convenient in cryptographic applications to instantiate such
prime-order groups using elliptic curves, such as those detailed in
{{SEC2}}. For some choices of elliptic curves (e.g. those detailed in
{{RFC7748}}, which require accounting for cofactors) there are some
implementation issues that introduce inherent discrepancies between
standard prime-order groups and the elliptic curve instantiation. In
this document, all algorithms that we detail assume that the group is a
prime-order group, and this MUST be upheld by any implementer. That is,
any curve instantiation should be written such that any discrepancies
with a prime-order group instantiation are removed. See {{ciphersuites}}
for advice corresponding to the implementation of this interface for
specific definitions of elliptic curves.

## Other conventions

- We use the notation `x <-$ Q` to denote sampling `x` from the uniform
  distribution over the set `Q`.
- For any object `x`, we write `len(x)` to denote its length in bytes.
- For two byte arrays `x` and `y`, write `x || y` to denote their
  concatenation.
- I2OSP and OS2IP: Convert a byte array to and from a non-negative
  integer as described in {{!RFC8017}}. Note that these functions
  operate on byte arrays in big-endian byte order.

All algorithm descriptions are written in a Python-like pseudocode. We
use the `ABORT()` function for presentational clarity to denote the
process of terminating the algorithm or returning an error accordingly.
We also use the `CT_EQUAL(a, b)` function to represent constant-time
byte-wise equality between byte arrays `a` and `b`. This function
returns `true` if `a` and `b` are equal, and `false` otherwise.

# OPRF Protocol {#protocol}

In this section, we define two OPRF variants: a base mode and verifiable
mode. In the base mode, a client and server interact to compute y =
F(skS, x), where x is the client's input, skS is the server's private
key, and y is the OPRF output. The client learns y and the server learns
nothing. In the verifiable mode, the client also gets proof that the
server used skS in computing the function.

To achieve verifiability, as in the original work of {{JKK14}}, we
provide a zero-knowledge proof that the key provided as input by the
server in the `Evaluate` function is the same key as it used to produce
their public key. As an example of the nature of attacks that this
prevents, this ensures that the server uses the same private key for
computing the VOPRF output and does not attempt to "tag" individual
servers with select keys. This proof must not reveal the server's
long-term private key to the client.

The following one-byte values distinguish between these two modes:

| Mode           | Value |
|:===============|:======|
| modeBase       | 0x00  |
| modeVerifiable | 0x01  |

## Overview {#protocol-overview}

Both participants agree on the mode and a choice of ciphersuite that is
used before the protocol exchange. Once established, the core protocol
runs to compute `output = F(skS, input)` as follows:

~~~
   Client(pkS, input, info)                 Server(skS, pkS)
  ----------------------------------------------------------
    blind, blindedElement = Blind(input)

                       blindedElement
                        ---------->

                  evaluatedElement, proof = Evaluate(skS, pkS, blindedElement)

                  evaluatedElement, proof
                        <----------

    unblindedElement = Unblind(blind, evaluatedElement, blindedElement, pkS, proof)
    output = Finalize(input, unblindedElement, info)
~~~

In `Blind` the client generates a token and blinding data. The server
computes the (V)OPRF evaluation in `Evaluation` over the client's
blinded token. In `Unblind` the client unblinds the server response (and
verifies the server's proof if verifiability is required). In
`Finalize`, the client produces a byte array corresponding to the output
of the OPRF protocol.

Note that in the final output, the client computes Finalize over some
auxiliary input data `info`. This parameter SHOULD be used for domain
separation in the (V)OPRF protocol. Specifically, any system which has
multiple (V)OPRF applications should use separate auxiliary values to
ensure finalized outputs are separate. Guidance for constructing info
can be found in {{!I-D.irtf-cfrg-hash-to-curve}}; Section 3.1.

## Context Setup

Both modes of the OPRF involve an offline setup phase. In this phase,
both the client and server create a context used for executing the
online phase of the protocol. Prior to this phase, keys (`skS`, `pkS`)
should be generated by calling a `KeyGen` function. `KeyGen`
generates a private and public key pair (`skS`, `pkS`), where `skS` is a
non-zero element chosen at random from the scalar field of the
corresponding group and `pkS = ScalarBaseMult(skS)`.

The base mode setup functions for creating client and server contexts are below:

~~~
def SetupBaseServer(suite, skS):
  contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ServerContext(contextString, skS)

def SetupBaseClient(suite):
  contextString = I2OSP(modeBase, 1) || I2OSP(suite.ID, 2)
  return ClientContext(contextString)
~~~

The verifiable mode setup functions for creating client and server
contexts are below:

~~~
def SetupVerifiableServer(suite, skS, pkS):
  contextString = I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableServerContext(contextString, skS)

def SetupVerifiableClient(suite, pkS):
  contextString = I2OSP(modeVerifiable, 1) || I2OSP(suite.ID, 2)
  return VerifiableClientContext(contextString, pkS)
~~~

Each setup function takes a ciphersuite from the list defined in
{{ciphersuites}}. Each ciphersuite has a two-byte field ID used to
identify the suite.

## Data Types {#structs}

The following is a list of data structures that are defined for
providing inputs and outputs for each of the context interfaces defined
in {{api}}. Data structure description uses TLS notation (see {{?RFC8446}},
Section 3).

This document uses the types `Element` and `Scalar` to denote elements of the
group `GG` and its underlying scalar field `GF(p)`, respectively. For notational
clarity, `PublicKey` is an item of type `Element` and `PrivateKey` is an item
of type `Scalar`. `SerializedElement` and `SerializedScalar` are serialized
representations of `Element` and `Scalar` types of length `Ne` and `Ns`,
respectively; see {{pog}}. `ClientInput` is an opaque byte string of arbitrary
length. `Proof` is a sequence of two `SerializedScalar` elements, as shown below.

~~~
SerializedScalar Proof[2];
~~~

## Context APIs {#api}

In this section, we detail the APIs available on the client and server
(V)OPRF contexts.

### Server Context

The ServerContext encapsulates the context string constructed during
setup and the (V)OPRF key pair. It has three functions, `Evaluate`,
`FullEvaluate` and `VerifyFinalize` described below. `Evaluate` takes
serialized representations of blinded group elements from the client as inputs.

`FullEvaluate` takes ClientInput values, and it is useful for applications
that need to compute the whole OPRF protocol on the server side only.

`VerifyFinalize` takes ClientInput values and their corresponding output
digests from `Finalize` as input, and returns true if the inputs match the outputs.

Note that `VerifyFinalize` and `FullEvaluate` are not used in the main OPRF
protocol. They are exposed as an API for building higher-level protocols.

#### Evaluate

~~~
Input:

  PrivateKey skS
  SerializedElement blindedElement

Output:

  SerializedElement evaluatedElement

def Evaluate(skS, blindedElement):
  R = GG.DeserializeElement(blindedElement)
  Z = skS * R
  evaluatedElement = GG.SerializeElement(Z)

  return evaluatedElement
~~~

#### FullEvaluate

~~~
Input:

  PrivateKey skS
  ClientInput input
  opaque info<1..2^16-1>

Output:

  opaque output[Nh]

def FullEvaluate(skS, input, info):
  P = GG.HashToGroup(input)
  T = skS * P
  issuedElement = GG.SerializeElement(T)

  finalizeDST = "VOPRF06-Finalize-" || self.contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(issuedElement), 2) || issuedElement ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(finalizeDST), 2) || finalizeDST

  return Hash(hashInput)
~~~

[[RFC editor: please change "VOPRF06" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

#### VerifyFinalize

~~~
Input:

  PrivateKey skS
  ClientInput input
  opaque info<1..2^16-1>
  opaque output[Nh]

Output:

  boolean valid

def VerifyFinalize(skS, input, info, output):
  T = GG.HashToGroup(input)
  element = GG.SerializeElement(T)
  issuedElement = Evaluate(skS, [element])
  E = GG.SerializeElement(issuedElement)

  finalizeDST = "VOPRF06-Finalize-" || self.contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(E), 2) || E ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(finalizeDST), 2) || finalizeDST

  digest = Hash(hashInput)

  return CT_EQUAL(digest, output)
~~~

[[RFC editor: please change "VOPRF06" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

### VerifiableServerContext

The VerifiableServerContext extends the base ServerContext with an
augmented `Evaluate()` function. This function produces a proof that
`skS` was used in computing the result. It makes use of the helper
functions `GenerateProof` and `ComputeComposites`, described below.

#### Evaluate

~~~
Input:

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindedElement

Output:

  SerializedElement evaluatedElement
  Proof proof

def Evaluate(skS, pkS, blindedElement):
  R = GG.DeserializeElement(blindedElement)
  Z = skS * R
  evaluatedElement = GG.SerializeElement(Z)

  proof = GenerateProof(skS, pkS, blindedElement, evaluatedElement)

  return evaluatedElement, proof
~~~

The helper functions `GenerateProof` and `ComputeComposites` are defined
below.

#### GenerateProof

~~~
Input:

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindedElement
  SerializedElement evaluatedElement

Output:

  Proof proof

def GenerateProof(skS, pkS, blindedElement, evaluatedElement)
  blindedElementList = [blindedElement]
  evaluatedElementList = [evaluatedElement]

  a = ComputeCompositesFast(skS, pkS, blindedElementList, evaluatedElementList)

  M = GG.DeserializeElement(a[0])
  r = GG.RandomScalar()
  a2 = GG.SerializeElement(ScalarBaseMult(r))
  a3 = GG.SerializeElement(r * M)

  pkSm = GG.SerializeElement(pkS)
  challengeDST = "VOPRF06-Challenge-" || self.contextString
  h2Input = I2OSP(len(pkSm), 2) || pkSm ||
            I2OSP(len(a[0]), 2) || a[0] ||
            I2OSP(len(a[1]), 2) || a[1] ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  c = GG.HashToScalar(h2Input)
  s = (r - c * skS) mod p
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

##### Fresh randomness

We note here that it is essential that a different `r` value is used for
every invocation. If this is not done, then this may leak `skS` as is
possible in Schnorr or (EC)DSA scenarios where fresh randomness is not
used.

#### ComputeComposites

The definition of `ComputeComposites` is given below. This function is
used both on generation and verification of the proof.

~~~
Input:

  PublicKey pkS
  SerializedElement blindedElements[m]
  SerializedElement evaluatedElements[m]

Output:

  SerializedElement composites[2]

def ComputeComposites(pkS, blindedElements, evaluatedElements):
  pkSm = GG.SerializeElement(pkS)
  seedDST = "VOPRF06-Seed-" || self.contextString
  compositeDST = "VOPRF06-Composite-" || self.contextString
  h1Input = I2OSP(len(pkSm), 2) || pkSm ||
            I2OSP(len(seedDST), 2) || seedDST

  seed = Hash(h1Input)
  M = GG.Identity()
  Z = GG.Identity()
  for i = 0 to m-1:
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(blindedElements[i]), 2) || blindedElements[i] ||
              I2OSP(len(evaluatedElements[i]), 2) || evaluatedElements[i] ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    Mi = GG.DeserializeElement(blindedElements[i])
    M = di * Mi + M
    Zi = GG.DeserializeElement(evaluatedElements[i])
    Z = di * Zi + Z

 return [GG.SerializeElement(M), GG.SerializeElement(Z)]
~~~

If the private key is known, as is the case for the server, this function
can be optimized as shown in `ComputeCompositesFast` below.

~~~
Input:

  PrivateKey skS
  PublicKey pkS
  SerializedElement blindedElements[m]
  SerializedElement evaluatedElements[m]

Output:

  SerializedElement composites[2]

def ComputeCompositesFast(skS, pkS, blindedElements, evaluatedElements):
  pkSm = GG.SerializeElement(pkS)
  seedDST = "VOPRF06-Seed-" || self.contextString
  compositeDST = "VOPRF06-Composite-" || self.contextString
  h1Input = I2OSP(len(pkSm), 2) || pkSm ||
            I2OSP(len(seedDST), 2) || seedDST

  seed = Hash(h1Input)
  M = GG.Identity()
  for i = 0 to m-1:
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(blindedElements[i]), 2) || blindedElements[i] ||
              I2OSP(len(evaluatedElements[i]), 2) || evaluatedElements[i] ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    Mi = GG.DeserializeElement(blindedElements[i])
    M = di * Mi + M

  Z = skS * M

 return [GG.SerializeElement(M), GG.SerializeElement(Z)]
~~~

### Client Context

The ClientContext encapsulates the context string constructed during
setup. It has three functions, `Blind()`, `Unblind()`, and `Finalize()`,
as described below.

#### Blind

We note here that the blinding mechanism that we use can be modified
slightly with the opportunity for making performance gains in some
scenarios. We detail these modifications in {{blinding}}.

~~~
Input:

  ClientInput input

Output:

  Scalar blind
  SerializedElement blindedElement

def Blind(input):
  blind = GG.RandomScalar()
  P = GG.HashToGroup(input)
  blindedElement = GG.SerializeElement(blind * P)

  return blind, blindedElement
~~~

#### Unblind

In this mode, `Unblind` takes only two inputs. The additional inputs indicated
in {{protocol-overview}} are only omitted as they are ignored. These additional
inputs are only useful for the verifiable mode, described in {{verifiable-unblind}}.

~~~
Input:

  Scalar blind
  SerializedElement evaluatedElement

Output:

  SerializedElement unblindedElement

def Unblind(blind, evaluatedElement, ...):
  Z = GG.DeserializeElement(evaluatedElement)
  N = (blind^(-1)) * Z
  unblindedElement = GG.SerializeElement(N)

  return unblindedElement
~~~

#### Finalize

~~~
Input:

  ClientInput input
  SerializedElement unblindedElement
  opaque info<1..2^16-1>

Output:

  opaque output[Nh]

def Finalize(input, unblindedElement, info):
  finalizeDST = "VOPRF06-Finalize-" || self.contextString
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              I2OSP(len(info), 2) || info ||
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

  PublicKey pkS
  SerializedElement blindedElement
  SerializedElement evaluatedElement
  Proof proof

Output:

  boolean verified

def VerifyProof(pkS, blindedElement, evaluatedElement, proof):
  blindedElementList = [blindedElement]
  evaluatedElementList = [evaluatedElement]

  a = ComputeComposites(pkS, blindedElementList, evaluatedElementList)
  c = GG.DeserializeScalar(proof[0])
  s = GG.DeserializeScalar(proof[1])

  M = GG.DeserializeElement(a[0])
  Z = GG.DeserializeElement(a[1])
  A' = (ScalarBaseMult(s) + c * pkS)
  B' = (s * M + c * Z)
  a2 = GG.SerializeElement(A')
  a3 = GG.SerializeElement(B')

  challengeDST = "VOPRF06-Challenge-" || self.contextString
  h2Input = I2OSP(len(pkS), 2) || pkS ||
            I2OSP(len(a[0]), 2) || a[0] ||
            I2OSP(len(a[1]), 2) || a[1] ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  expected_c  = GG.HashToScalar(h2Input)

  return CT_EQUAL(expected_c, c)
~~~

#### Unblind {#verifiable-unblind}

~~~
Input:

  Scalar blind
  SerializedElement evaluatedElement
  SerializedElement blindedElement
  PublicKey pkS
  Scalar proof

Output:

  SerializedElement unblindedElement

def Unblind(blind, evaluatedElement, blindedElement, pkS, proof):
  if VerifyProof(pkS, blindedElement, evaluatedElement, proof) == false:
    ABORT()

  Z = GG.DeserializeElement(evaluatedElement)
  N = (blind^(-1)) * Z
  unblindedElement = GG.SerializeElement(N)

  return unblindedElement
~~~

## Batching

Clients that need multiple verifiable evaluations would make as much requests
to the server. Batching the inputs enables the server to evaluate them all
individually and to compute a single NIZK proof for the whole set at once.

With this technique, the client sends a set of blindedElements to the server,
and the server responds with the set of evaluatedElements and a single proof object
(proofC and proofS).

The optimization takes place in the ComputeComposites function, and therefore
benefits both the server and the client. Hence, for N blinded inputs from the
client, instead of having N roundtrips for fetching N evaluations and N proofs,
we would bring that down to a single roudtrip carrying N evaluations and 
one proof.

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
- `Hash`: A cryptographic hash function that is indifferentiable from a
  Random Oracle, whose output length is Nh bytes long.

This section specifies ciphersuites with supported groups and hash functions.

Applications should take caution in using ciphersuites targeting P-256
and ristretto255. See {{cryptanalysis}} for related discussion.

## OPRF(ristretto255, SHA-512)

- Group: ristretto255 {{!RISTRETTO=I-D.irtf-cfrg-ristretto255-decaf448}}
  - HashToGroup(): hash_to_ristretto255
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions, and `expand_message` = `expand_message_xmd`
    using SHA-512.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L = 48, and expand_message_xmd
    with SHA-512.
  - Serialization: Both group elements and scalars are encoded in Ne = Ns = 32
    bytes. For group elements, use the 'Encode' and 'Decode' functions from
    {{!RISTRETTO}}. For scalars, ensure they are fully reduced modulo p and
    in little-endian order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0001

## OPRF(decaf448, SHA-512)

- Group: decaf448 {{!RISTRETTO}}
  - HashToGroup(): hash_to_decaf448
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions, and `expand_message` = `expand_message_xmd`
    using SHA-512.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L = 84, and `expand_message_xmd`
    with SHA-512.
  - Serialization: Both group elements and scalars are encoded in Ne = Ns = 56
    bytes. For group elements, use the 'Encode' and 'Decode' functions from
    {{!RISTRETTO}}. For scalars, ensure they are fully reduced modulo p and
    in little-endian order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0002

## OPRF(P-256, SHA-256)

- Group: P-256 (secp256r1) {{x9.62}}
  - HashToGroup(): P256_XMD:SHA-256_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L = 48, and `expand_message_xmd`
    with SHA-256.
  - Serialization: Elements are serialized as Ne = 33 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 32 byte strings by fully reducing the value modulo p and in big-endian
    order.
- Hash: SHA-256, and Nh = 32.
- ID: 0x0003

## OPRF(P-384, SHA-512)

- Group: P-384 (secp384r1) {{x9.62}}
  - HashToGroup(): P384_XMD:SHA-512_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L = 72, and `expand_message_xmd`
    with SHA-512.
  - Serialization: Elements are serialized as Ne = 49 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 48 byte strings by fully reducing the value modulo p and in big-endian
    order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0004

## OPRF(P-521, SHA-512)

- Group: P-521 (secp521r1) {{x9.62}}
  - HashToGroup(): P521_XMD:SHA-512_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L = 98, and `expand_message_xmd`
    with SHA-512.
  - Serialization: Elements are serialized as Ne = 67 byte strings using
    compressed point encoding for the curve {{SEC1}}. Scalars are serialized as
    Ns = 66 byte strings by fully reducing the value modulo p and in big-endian
    order.
- Hash: SHA-512, and Nh = 64.
- ID: 0x0005

# Security Considerations {#sec}

This section discusses the cryptographic security of our protocol, along
with some suggestions and trade-offs that arise from the implementation
of an OPRF.

## Security properties {#properties}

The security properties of an OPRF protocol with functionality y = F(k,
x) include those of a standard PRF. Specifically:

- Pseudorandomness: F is pseudorandom if the output y = F(k,x) on any
  input x is indistinguishable from uniformly sampling any element in
  F's range, for a random sampling of k.

In other words, consider an adversary that picks inputs x from the
domain of F and evaluates F on (k,x) (without knowledge of randomly
sampled k). Then the output distribution F(k,x) is indistinguishable
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

## Cryptographic security {#cryptanalysis}

Below, we discuss the cryptographic security of the (V)OPRF protocol
from {{protocol}}, relative to the necessary cryptographic assumptions
that need to be made.

### Computational hardness assumptions {#assumptions}

Each assumption states that the problems specified below are
computationally difficult to solve in relation to a particular choice of
security parameter `sp`.

Let GG = GG(sp) be a group with prime-order p, and let GF(p) be a finite
field of order p.

#### Discrete-log (DL) problem {#dl}

Given G, a generator of GG, and H = hG for some h in GF(p); output h.

#### Decisional Diffie-Hellman (DDH) problem {#ddh}

Sample uniformly at random d in {0,1}. Given (G, aG, bG, C), where

- G is a generator of GG;
- a,b are elements of GF(p);
- if d == 0: C = abG; else: C is sampled uniformly at random from GG.

Output d' == d.

### Protocol security {#protocol-sec}

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

### Q-strong-DH oracle {#qsdh}

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
log_2(Q) bits.

As an example, suppose that a group instantiation is used that provides
128 bits of security against discrete log cryptanalysis. Then an
adversary with access to a Q-sDH oracle and makes Q=2^20 queries can
reduce the security of the instantiation by log_2(2^20) = 20 bits.

Notice that it is easy to instantiate a Q-sDH oracle using the OPRF
functionality that we provide. A client can just submit sequential
queries of the form (G, k * G, (k^2)G, ..., (k^(Q-1))G), where each
query is the output of the previous interaction. This means that any
client that submits Q queries to the OPRF can use the aforementioned
attacks to reduce the security of the group instantiation by log_2(Q) bits.

Recall that from a malicious client's perspective, the adversary wins if
they can distinguish the OPRF interaction from a protocol that computes
the ideal functionality provided by the PRF.

### Implications for ciphersuite choices

The OPRF instantiations that we recommend in this document are informed
by the cryptanalytic discussion above. In particular, choosing elliptic
curves configurations that describe 128-bit group instantiations would
appear to in fact instantiate an OPRF with 128-log_2(Q) bits of
security.

In most cases, it would require an informed and persistent attacker to
launch a highly expensive attack to reduce security to anything much
below 100 bits of security. We see this possibility as something that
may result in problems in the future. For applications that cannot
tolerate discrete logarithm security of lower than 128 bits, we
recommend only implementing ciphersuites with IDs: 0x0002, 0x0004, and
0x0005.

## Hashing to curve

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

## Timing Leaks

To ensure no information is leaked during protocol execution, all
operations that use secret data MUST run in constant time. Operations that
SHOULD run in constant time include all prime-order group operations and
proof-specific operations (`GenerateProof()` and `VerifyProof()`).

## Key rotation {#key-rotation}

Since the server's key is critical to security, the longer it is exposed
by performing (V)OPRF operations on client inputs, the longer it is
possible that the key can be compromised. For example, if the key is kept
in circulation for a long period of time, then it also allows the
clients to make enough queries to launch more powerful variants of the
Q-sDH attacks from {{qsdh}}.

To combat attacks of this nature, regular key rotation should be
employed on the server-side. A suitable key-cycle for a key used to
compute (V)OPRF evaluations would be between one week and six months.

# Additive blinding {#blinding}

Let `H` refer to the function `GG.HashToGroup`, in {{pog}} we assume
that the client-side blinding is carried out directly on the output of
`H(x)`, i.e. computing `r * H(x)` for some `r <-$ GF(p)`. In the
{{!I-D.irtf-cfrg-opaque}} document, it is noted that it may be more efficient to use
additive blinding (rather than multiplicative) if the client can
preprocess some values. For example, a valid way of computing additive
blinding would be to instead compute `H(x) + (r * G)`, where `G` is the
fixed generator for the group `GG`.

The advantage of additive blinding is that it allows the client to
pre-process tables of blinded scalar multiplications for `G`. This may
give it a computational efficiency advantage (due to the fact that a
fixed-base multiplication can be calculated faster than a variable-base
multiplication). Pre-processing also reduces the amount of computation
that needs to be done in the online exchange. Choosing one of these
values `r * G` (where `r` is the scalar value that is used), then
computing `H(x) + (r * G)` is more efficient than computing `r * H(x)`.
Therefore, it may be advantageous to define the OPRF and VOPRF protocols
using additive (rather than multiplicative) blinding. In fact,
the only algorithms that need to change are `Blind` and `Unblind` (and
similarly for the VOPRF variants).

We define the variants of the algorithms in {{api}} for performing
additive blinding below, called `AdditiveBlind` and `AdditiveUnblind`,
along with a new algorithm `Preprocess`. The `Preprocess` algorithm can
take place offline and before the rest of the OPRF protocol. `AdditiveBlind`
takes the preprocessed values as inputs. `AdditiveUnblind` takes the
preprocessed values and evaluated element from the server as inputs.

## Preprocess

~~~
Input:

  PublicKey pkS

Output:

  Element blindedGenerator
  Element blindedPublicKey

def Preprocess(pkS):
  blind = GG.RandomScalar()
  blindedGenerator = ScalarBaseMult(blind)
  blindedPublicKey = blind * pkS

  return blindedGenerator, blindedPublicKey
~~~

## AdditiveBlind

~~~
Input:

  ClientInput input
  Element blindedGenerator

Output:

  SerializedElement blindedElement

def AdditiveBlind(input, blindedGenerator):
  P = GG.HashToGroup(input)
  blindedElement = GG.SerializeElement(P + blindedGenerator) /* P + ScalarBaseMult(r) */

  return blindedElement
~~~

## AdditiveUnblind

~~~
Input:

  Element blindedPublicKey
  SerializedElement evaluatedElement

Output:

 SerializedElement unblindedElement

def AdditiveUnblind(blindedPublicKey, evaluatedElement):
  Z = GG.DeserializeElement(evaluatedElement)
  N := Z - blindedPublicKey

  unblindedElement = GG.SerializeElement(N)

  return unblindedElement
~~~

Let `P = GG.HashToGroup(input)`. Notice that AdditiveUnblind computes:

~~~
Z - blindedPublicKey = k * (P + r * G) - r * pkS
                     = k * P + k * (r * G) - r * (k * G)
                     = k * P
~~~

by the commutativity of the scalar field. This is the same
output as in the `Unblind` algorithm for multiplicative blinding.

Note that the verifiable variant of `AdditiveUnblind` works as above but
includes the step to `VerifyProof`, as specified in {{verifiable-client}}.

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
Tatiana Bradley, Sofía Celi, Frank Denis, and Bas Westerbaan also
provided helpful input and contributions to the document.

--- back

# Test Vectors

This section includes test vectors for the (V)OPRF protocol specified
in this document. For each ciphersuite specified in {{ciphersuites}},
there is a set of test vectors for the protocol when run in the base
mode and verifiable mode. Each test vector lists the batch size for
the evaluation. Each test vector value is encoded as a hexadecimal
byte string. The label for each test vector value is described below.

- "Input": The client input, an opaque byte string.
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
- "UnblindedElement": The unblinded element output by `Unblind()`,
  a serialized `Element` of `Ne` bytes long.
- "Info": The client `info` parameter, an opaque byte string.
- "Output": The OPRF output, a byte string of length `Nh` bytes.

Test vectors with batch size B > 1 have inputs separated by a comma
",". Applicable test vectors will have B different values for the
"Input", "Blind", "BlindedElement", "EvaluationElement",
"UnblindedElement", and "Output" fields.

The server key material, pkSm and skSm, are listed under the mode for
each ciphersuite. Both pkSm and skSm are the serialized values of
pkS and skS, respectively, as used in the protocol.

## OPRF(ristretto255, SHA-512)

### Base Mode

~~~
skSm = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf8
e03
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 5cccd309ec729aebe398c53e19c0ab09c24a29f01036960bdad
109852e7bdb44
EvaluationElement = 86bd5eeabf29a87cb4a5c7207cb3ade5297e65f9b74c979b
d3551891f4b21515
UnblindedElement = 3c7f2d901c0d4f245503a186086fbdf5d8b4408432b25c516
3e8b5a19c258348
Info = 736f6d655f696e666f
Output = 53c8441196248d38e0cb0cff2434962cce879069f15fe78bd56474e0bc3
24df1cbff4dbbf190e2269e07e02496ec19674e4e8d316d4e211d9240de91027228d
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 227d63ca69e93bd062193c1e97fff3d5ebf628f646009d77c4e
22ba6429be154
EvaluationElement = 063b91a12e7cbb98dfeb75d8a7eeb83aacf9fd6df7e0b419
7466fb77a27fa631
UnblindedElement = 804ec6774764ed50a0bbad0a5f477aa04df7323acab8f98ca
6e468b7790bca4c
Info = 736f6d655f696e666f
Output = 96fd02b11327e318655773bff4ebe3608090d1980c020d7cf399afdaae4
50b5d03d9fde445cd71bde6b0d186982e59f7f2d858fb6739a1ca26a037ff039f4f3
1
~~~

### Verifiable Mode

~~~
skSm = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9dbcec831b8c681
a09
pkSm = eee7a9c7fec3460c27c160c683d46a4fd18f537c055c3998748b8e4cd8f29
b3e
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 89c61a42c8191a5ca41f2fe959843d333bcf43173b7de4c5c119e0e0d8b0
e707
BlindedElement = 78a09c84ecf234df4a46c3695f1be3b9c045476b6826bc7bc78
27c29a4978022
EvaluationElement = 5679669e01363a05e3da803c0b0cd76bffecd8048ec81eee
b391b7301e93aa2e
UnblindedElement = 269a8a1f845eb7a767b8b2706198388bad8271bdbb5fac48e
e2b21116395631f
EvaluationProofC = 673b5e2d75540afdacd7b6183c3a84323f1822b60c8ee9d90
088fa3b3a508908
EvaluationProofS = a1edd24e73bffabff314d9cc7ad1af6f0b2cae7ec88bcef08
e7efedc9d0eb00e
Info = 736f6d655f696e666f
Output = 851f5e0b699b296cfd97428de293be225b687559962106a3701df6c8b66
56c45bcb8e2cc6e9608d59d9a64bbcaa8ecfc08745f3b5c279fdef5f49e5696e4244
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 8d665022e9ad52b74c04a426f8af36205e81997c2175079b22a0b0a16270
c909
BlindedElement = 8e7060a2608dbbb1ba03922d7c633daca752400da8ee75af792
5e1affcf99871
EvaluationElement = a8208b606a6af1f7e2c5b155f908197aa786aba72585103b
ba35fa9ad703f426
UnblindedElement = ccfa691bc7c0bd5a19546bc748fecca1661480fe304e881b4
ce661766ac2cf76
EvaluationProofC = 025e0a1e109baa97cea27550cf432d596e48bab2b1b0cf95c
9af25fd89431e06
EvaluationProofS = 295f8cb05f90f6c28b9e707fe5acc29dbe31b50375a64403f
965116afe5d7501
Info = 736f6d655f696e666f
Output = afd882f35e4ae086fe00668b334f4290f70f63c89559b0b990d7b1d60c6
157cc0ecb80e76e515fe66c24c06ef3a7638493431ad43cf00e03e980b13a2009b4e
e
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186a9706137886d
ce08,8bcb0b70dac18de24eef12e737d6b28724d3e37774e0b092f9f70b255defaf0
4
BlindedElement = b8a0b4d0c056628131cd8ed1ea87cacecf6e09740c14a32c3e0
a2820e43afb3c,50a6b8dc62e95ac34320d7ceac08f4002710fdc49e56bde78b092d
01cad93e50
EvaluationElement = 12619d1c02de52189fa92f312eabe3062f627f0a75ccacd4
16d6dd2b71286e31,0093e963653200cacd9215833086a59e333db4b5f260db6a44c
81e8c7de59a5e
UnblindedElement = 269a8a1f845eb7a767b8b2706198388bad8271bdbb5fac48e
e2b21116395631f,ccfa691bc7c0bd5a19546bc748fecca1661480fe304e881b4ce6
61766ac2cf76
EvaluationProofC = 5ed544c7e6b8f8ab3d15d1650577a76107ba28986c6a600f4
eceff259110e40a
EvaluationProofS = 1cf74024f8d29c73d92d536b60e196d78bdeaf6c3481b62e8
cd8cf85c128be03
Info = 736f6d655f696e666f
Output = 851f5e0b699b296cfd97428de293be225b687559962106a3701df6c8b66
56c45bcb8e2cc6e9608d59d9a64bbcaa8ecfc08745f3b5c279fdef5f49e5696e4244
e,afd882f35e4ae086fe00668b334f4290f70f63c89559b0b990d7b1d60c6157cc0e
cb80e76e515fe66c24c06ef3a7638493431ad43cf00e03e980b13a2009b4ee
~~~

## OPRF(decaf448, SHA-512)

### Base Mode

~~~
skSm = c4d5a15f0d5ffc354e340454ec779f575e4573a3886ab5e57e4da2985cea9
e32f6d95539ce2c7189e1bd7462a21723e92e2e9955ef20a92c
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 5843ebd3618d4fad8b7288477da50bed9befa58af639ddd950fec34205f8
a4f166fadcb8fa71a3ffdd2e98f422bf7b99be19f7da1fab583c
BlindedElement = 84be45bb776f8f15e8ed716663a010773cb44ad3b2c4dc66948
c2972bac99913308f160737e3f32a44349584a4b6ef4adf924f5fcc192d17
EvaluationElement = a6cf272ceb18e8f6abcf9216819b0b2265ad10502633d087
1b102b5ea7f574d9c6852af32f1082b578878bd09709df1897aa064f52b16414
UnblindedElement = 0cedeea1ef6934cff2d95b2af842806d7364312d8845504ae
31dac84511a92285d20cb281e13797f37b4415f117915106b9bf3a0a462eee9
Info = 736f6d655f696e666f
Output = e0409c1eaa2cb3166cb4f8799c8b8054fc30139caf3339ac541438af117
a0a6f7a03db76fa83aaa84a5ce8145341fb707bf06b2e9aa027b5613a7ddb09f3fc7
b
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5a9d35a225ec6340149a0aaf99870019c3d002aa4cfcf281657cf36fe562
bc60d9133e0e72a74432f685b2b620a55561604bb5783ca7f11d
BlindedElement = f0d1f1eb43b85e6dde38c0526151db3745b672667bef97bb0a3
553e191ad47f8c04e4a4c1588f028afecc170f15baeea2d44e86fe67982f8
EvaluationElement = f60cf47549fa62e72ae7253a4d42a8fc6ca70e0ac0ddc319
30627692eb3096792cf988115f792c99c03b08b0a5d07f2a2b7141dcb8c73cb9
UnblindedElement = a8d2cfdb49a2d1409a53656cbdf12829ccb6fcad73807727d
c2eaa4499e45f0af4cce88b443bedfc4cd08e9cdede61fd243e089a4f010a0f
Info = 736f6d655f696e666f
Output = eda4b68203b190cf690214f6068d174d795406a106bbe07f8a20fd66a83
42bb2a31a49739b593544601039613be85900f4ae79711e8a706c2a74174d4c8677b
2
~~~

### Verifiable Mode

~~~
skSm = eb9e7aea3e4839413997e020f9377b63c13584156a09a46dd2a425c41eac0
e313a47e99d05df72c6e1d58e654a5ee9354b1150602f6adf2d
pkSm = 3ae16a2f8c506ebef74fafa9190e19447b07772e3077300b758411b941d8d
61f6b1840b35a73578f6aeb09e1a302a9d68f1db1cb34e90014
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = d83e00cbb8559f84cb7a221b235b0950a0ab553f03f10e1386abe954011b
7da62bb6599418ef90b5d4ea98cca1bcd65fa514f189d2b31a07
BlindedElement = 54c5fd05a11cd041f09a80db5e8a327b654d24563178b25a128
b549d32857167062e3ba259de5e938e3635af9d17fdb3cc38fe43d21951b5
EvaluationElement = 5e284dc6fecae55bb6263a03ca772979ea559b28c8ba316d
4fe3e8c6c38649455982f31f84679aa5db3264613671ab238a9950a28b5d6471
UnblindedElement = 62a06f98dd6e56123081d519d3926ef6a0b3dd02659ec470b
f60ad2bdab709fe11d88e74168d1110245cda7ad654340ea2430ca86974e166
EvaluationProofC = c4af97abc45ca793c288bcf789fddb91ba97f4facb814a920
b58f06174b67accd626d212126c14db4276d4e0bd196dad3c1183c6d8e5fe3d
EvaluationProofS = c664d2dabd679ab657ac57a195bfbcdb82b7fbf105cc0118c
1b568875eafb64d504d72a7e2dc697b85358859115c51ee50ae348b411a841d
Info = 736f6d655f696e666f
Output = 77e96be0813c333a233518fe87dc845b5b58944e428a64c1489e04a15f4
128a818198fcd65195a8435717ab6a87815bfb8fd220ee9869c9b6e6ea00b7840c1b
f
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = ec86c5379228da260159dc24f7c5c2483a81aff8d9ff676ebd81db28eb1e
147561c478a3f84cbf77037f010272fd51abcff08ac9a7fcea16
BlindedElement = 9ca39b9c495b8fb1824923cd4b564a37e3921c7c6eeb799d448
9038f8b24388e858e67a461b776318eeb7fc1c59eb7e3f32b341a5b5d2308
EvaluationElement = ecf902b012dbd2cdf5de49ca99e2251948c93d345f7d4a6d
42b5ea5cd321ccdded0f89cfd63b3c77afe22924924814299e595a8656c2f56b
UnblindedElement = ba5084a399f858f5e43c959f207ce4707d63e921d82f1dc9c
aadb4361b56953c63ea8d41baadbf2d0ba63ab490cbcc8856d9d53e46efc7d4
EvaluationProofC = d5672632ceb780f677397bcb06a362e7169f4829369e6d044
372294618677e3f2032a85d9ce8f1e41bd8194f35c81bc799927720ba763934
EvaluationProofS = bf4db6f201ba01cf6e58b1be9491cc5b2aa8ddd5498c0dbdf
fa99bd7f6539d36a9c6737e1302af33e6ab4a48b8bec87ef4f41296fff11a14
Info = 736f6d655f696e666f
Output = 63c9aad6d56f8ec8de915a742c8543202837bdba0350770511049bf0b54
6b1adffac5ca550c15ed0f94b89053a61a6ff52df629b8f91793b489b547bf5b9566
2
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5b6f602b4b20a570a697452b3ddbb7d0e29363adebbcb5673294396b0b4e
7edc4adfc97a75132d92a1da241baff84fada3e7b12d569c0b3f,ad9ba734d54c2b2
4bff0ef6310404b5c05d60d7c258cea6500229ee057507c3e53534ad9db9f6df6ce5
15d1b8017923b65cada19e7a49a18
BlindedElement = ae30869b3292b406ffae15145f8d056232cc6c6b6ea9d49004f
d3a2492aa2770e28b0ee344ad438180deacf501ec54cae7c1f8b0c4e6958b,54fbd3
7ead128577c7536a862d018b29c3dbc9da09e6cbb9d7a96013b6ac8f9d0b1599cfd5
9292ea9ef95240c9e8796b41e49b3037b4984c
EvaluationElement = 92fe4293f5dad22e44e91659b20ee0e5fdf5f805d9148ee4
9573081aea607cf9e05ce16c802cf76db06b3f95d40175829c2950fd5ad1a82d,e60
a930f90ab1eca807b057200fb997c68808aab811cbde365451f86c4132684e613410
b00f39b7f080fd37ed4149cf3df5e7152ff8004b1
UnblindedElement = 62a06f98dd6e56123081d519d3926ef6a0b3dd02659ec470b
f60ad2bdab709fe11d88e74168d1110245cda7ad654340ea2430ca86974e166,ba50
84a399f858f5e43c959f207ce4707d63e921d82f1dc9caadb4361b56953c63ea8d41
baadbf2d0ba63ab490cbcc8856d9d53e46efc7d4
EvaluationProofC = e9dba5de07f66d9fc40707c6bb0c69b893e0291d76402d829
76696ee0247b94bb6697e8d5e93963e48e057ad5978c49a4f8c781ff2004c1e
EvaluationProofS = 9d1227714a1807d72566bfc06ae807e8900bce5c7fd6511ad
112a3734b3c192f3b9979c3357dee5c7df933830c299a5422d0e2d7ebe59a21
Info = 736f6d655f696e666f
Output = 77e96be0813c333a233518fe87dc845b5b58944e428a64c1489e04a15f4
128a818198fcd65195a8435717ab6a87815bfb8fd220ee9869c9b6e6ea00b7840c1b
f,63c9aad6d56f8ec8de915a742c8543202837bdba0350770511049bf0b546b1adff
ac5ca550c15ed0f94b89053a61a6ff52df629b8f91793b489b547bf5b95662
~~~

## OPRF(P-256, SHA-256)

### Base Mode

~~~
skSm = 2902c13bdc9993d3717bda68fc080b9802ae4effd5dc972d9f9fb3bbbf106
ade
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0
df39
BlindedElement = 03774b90bbb29af011e08dcb31ec7aa5f902afe02338f96d6b8
17400f7d77d987f
EvaluationElement = 02350c80b07aa03da012f7d9162645673bd3535a89b96bf5
2f4f0d9b026610b325
UnblindedElement = 036421a5471d3efcdd941dd85b511939ffbee330d8c96ac5e
1a529cc428eab3aeb
Info = 736f6d655f696e666f
Output = abd0a95b0fd52a26ef367199b96071b8a3d40c4b403a8b97fc5b567f27f
b080d
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = b5e8f3c63b86ae88d9ce0530b01cb1c23382c7ec9bdd6e75898e4877d8e2
bc17
BlindedElement = 03ec4301d1d42a4582588a9258413a28cd997de3468e198f463
eadbffcc2adeaa5
EvaluationElement = 03807af5cbdbf6c56842f866b87c69f7b9fc4ab8d891353d
f97395f63145c9aea2
UnblindedElement = 03bbf0692f18ec393df3755ae5fcf0473ba4c924fc32dd118
40dd196bdf15471c0
Info = 736f6d655f696e666f
Output = 9f2ff595e24982d3e8338a596783b673e71620d9319f55817742933a89c
7ff55
~~~

### Verifiable Mode

~~~
skSm = 4283efb9cd1ee4061c6bf884e60a877321ece4f9b6ffd01ce82082545413b
d9c
pkSm = 03c335d2eebd0ccbd5b8a145c9c2ee7452f401dcd4301ab138b0b56fc1c72
769cb
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09
589f
BlindedElement = 024829172675a0f6036657cd5d9eb0cfb97cad2eae79dfe5166
095d4db0fe4a49c
EvaluationElement = 02fef714dc9464983baca86fee8857a6afec020a9ea9440d
31f141c5957e04f494
UnblindedElement = 03e0d6dcbce22e122a441c27828bf5867ae91ef0287af662e
24f47b31e2bc92ae2
EvaluationProofC = 2d0c60ea2211b48ef1c3924d5243fe81a1c9155c6578af08e
664565d3816ac6a
EvaluationProofS = 074d637aa4522b51dcee362a9ed306b6b8a54727f7b4e5ab8
c3b3e1c6e5ce02c
Info = 736f6d655f696e666f
Output = 25820403dd3523604618258da6a41a6729a8d0a83dbafb6f579d1d4dcb2
edaa3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 076f08753056c186437ded8ee22f96e44bd5b6ec07cb131d51cf1324c123
8699
BlindedElement = 03de136afec7e193e73d28d83e84a2b31b4532da77b8ee9a053
ad209873e3841cb
EvaluationElement = 03e2ce505dcac913ed1e29c1dd34cc3e3079887ee5775420
1e0642ede25538e27e
UnblindedElement = 037dd1c0daf493d8a2ab3a2b4fe2528caec6aba63d0a48303
2860abf8bd8ea74f3
EvaluationProofC = 238f041989e3e71ff5ee25e86566c76e4366baa819bbfbfbc
4757cdd2f3fc6d5
EvaluationProofS = 766c01412f32e6740972e4b5fda0563e3720faecdd4aaedeb
ba0bba84248aa04
Info = 736f6d655f696e666f
Output = 6683239f5e1c611d775fe9c73014bc832fc966c5009e268fb955c9bf974
abb58
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = bb1876a7f7165ac7ec79bfd5213ea2e374252f29a6e19915f81b0c7dcea9
3ce7,e04f47e8d2554a5ebd83679b4c1e67ed82f2891751aa7094602be672c324929
b
BlindedElement = 0245a57f9e991bb3661c3343772cdb16cc16217d441e0847c7d
4ae8eaad41a980f,0375e7898d32f42e0479a8bd7017378604df8d3eddee91f3a5e7
0df7126fe8050d
EvaluationElement = 030eb61d8599b8703ae0cd1c5b988d4dc9bf77645c2ce9b5
0f6e8bcee1149cd5a5,03f6055d4cb2471940ed0ee2b647a0cf89a283484c29febbf
2d49a7d77e7f23c4c
UnblindedElement = 03e0d6dcbce22e122a441c27828bf5867ae91ef0287af662e
24f47b31e2bc92ae2,037dd1c0daf493d8a2ab3a2b4fe2528caec6aba63d0a483032
860abf8bd8ea74f3
EvaluationProofC = ffeb7a787565a5d23f0b3b5c2c6064ee1d0aa69e98f7bbe04
7c14a7b924f11f3
EvaluationProofS = f8c99cb8557db8f77509a041a5fb9bf7df9d50e538cb68bba
59adefc7b4a6985
Info = 736f6d655f696e666f
Output = 25820403dd3523604618258da6a41a6729a8d0a83dbafb6f579d1d4dcb2
edaa3,6683239f5e1c611d775fe9c73014bc832fc966c5009e268fb955c9bf974abb
58
~~~

## OPRF(P-384, SHA-512)

### Base Mode

~~~
skSm = 06cc9faa9dc7ab251997738a3a232f352c2059c25684e6ccea420f8d0c793
f9f51171628f1d28bb7402ca4aea6465e27
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = ae86286729214a1ba9a359ab01833477b8cb91932d0c81667a0e3244b896
ac141b538ff23749be19e92df82df1acd3f7
BlindedElement = 0256ec771e8a7b770ff9ab40efb499279ed9a71d36ab6bc7d40
cd64565c66c2db285b8fe58f47e68bf3c02b98c90684aaa
EvaluationElement = 02bdf50a96769acb293d3ba11a124c6b784e921d2d3d3112
eb696a998a0a3464c9c27f6eddf8a270ac721678e75e7df344
UnblindedElement = 0339cc6aa5b5ef9bd0ba57b1f317e17d8aac3311c1fd6e581
ae84b4af19f4d4efd2877a8e127a7141cbedbbebd77826192
Info = 736f6d655f696e666f
Output = fd1266a98b2b0ca3971fa82295f1893a548088aa7bd500afa915f0745b8
9b1f94a6f4c08a68e8a79a0cc958f81d7c2badfd797509d7b987ca295b91a9786b91
4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 523eff8db014d9b8b53ad7b0e149b0938b45f65717a40c38f671d326e196
e8a21bf6cfd40327a95f1ccfc82a9f83a75e
BlindedElement = 03a4badb8d617e78f7df557e183d01e1284920f5e84bc916b41
85b20f57129a09a301e57d4ea93463f398c31b52934e91c
EvaluationElement = 029fffdcadf404bec3ac2a120a0e4df38c6563e691cd256c
6fe6adaabb0362097b6026ae3c6e2995cf5f0c18548e6706af
UnblindedElement = 035540b79d5a64cb696cf0310692cbadd391d5de2f19f838b
17264d5117a0813489c9a28a604e3ed56b00aeb5931391cb1
Info = 736f6d655f696e666f
Output = 94ae0bd412a7b5cf1318f530d8434c9c64ddceed221fab1a958f0f6ee18
fe598b2fb51c65d3d2e1aa5ff724e718e0b62178dbd4019bdf051b7edc8c71dcd915
1
~~~

### Verifiable Mode

~~~
skSm = 32370deb7c3c17d9fc7cb4e0ce646e04e42d638e0fa7a434ed340772a8b5d
6253d35895f4cff282d86b2358d89a82ee7
pkSm = 023112a158597bf66974ec2391209063aa489fc1e98fec51be3a81aeeac03
b94dea1deee98515dc73c060a1432913d1a5d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = bbabe8add48bcd149ff3b840dc8a5d2483705fcc9a39607288b935b0797a
c6b3c4b2e848823ac9ae16b3a3b5816be035
BlindedElement = 0255b8e051b51b644548304894e2f41b012075a807d5dc27169
7322cc057e19834c6f47e24309e2e102e44c92c321694a0
EvaluationElement = 03fbffe94ed4b87bbee72fbdc3d7698bc7f9e39af32a1612
ba1c4c2d626678754c0675644a67d7a9e6fdcb2da882018328
UnblindedElement = 03f76b2ddddcce5db5504f77d07eeccd8302436818c4882b2
93499f31255b139aa3ed920002dc2e201b725de580b251852
EvaluationProofC = 9bc67e891fcd80112dfe7deb70182bebe509b470fe0f194a0
3d16cdcdb2a3a8008ec19ba26366ca6bb8809af6a44e7e0
EvaluationProofS = 73a2a536c65b6fff02eb9615d7c08490f3d0cedf789a6d791
cb3b98592f5e1941fa92746fb73f186b534e27b540e0c2c
Info = 736f6d655f696e666f
Output = 5dba66546a633215df3fb6dc002655f43ed07f497fd1b4ee6f2214fd657
8aebbceabfb3ce03ce005f0f457b6764e74dfa78d72ee5cc21e167a17c67ce86847e
3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0470f06169bee12cf47965b72a59946ca387966f5d8331eab82117c88bbd
91b8954e16c0b9ceed3ce992b198be1ebfbb
BlindedElement = 0358930b1c57b54bf884d0b76904f11a4a139935e94ddc55287
678f041e9a9dc1f435a68f74df8c9d5febd1a4d910ad9fa
EvaluationElement = 02636fea7f2b916749f2eab123a9eff087688d8e5a7c2d95
df91b6defe1e0180c5272c9866ae95ad9697ae96c70967cc84
UnblindedElement = 0330d4bfdc5dab25ed4813570b4975b16a6fd0202bb2373a0
0edcb008ac105f51216837973cd29f20744eac13619ce28a2
EvaluationProofC = a79fe0ddd80f3ad91257ad638e6f80328c0779b3e9f90ef14
bb0be6e9131bb268b030562302eb0387ed95fbd6effb086
EvaluationProofS = af5524e526e0649fce351adcf199251a0f3dc2ec93c885652
09a64c95ebe5b03ed88f75e1cd1835bf87b3c1c8c3519e6
Info = 736f6d655f696e666f
Output = 558a6bcecaab839fe9a7020352655cd79ddca1c7c29ac1f062a4a96a69b
59fd3b385a11481f6fb4c2d8900d1c6897b5d5a6b14c2bd31dc7282d643b9630529a
d
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = a0d61b2f5a8a2a1143368327f3077c68a1545e9aafbba6a90dc0d4094ba4
283237211e139f306fc904c2d4fe4cc69c0b,90320718eff747e2482562df55c99bf
9591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6d688f70cf205f782fa12
BlindedElement = 0332a05819c8b2c1165d104b43e0b3e2fd49b17dd5e2a3c84bd
a805dbcebf20860d3a063d552f1190c6f79e64f01e6aee5,0337e5bd41e1b763aac3
39f488b158014a31addc5a8c69cdd4fcdc11305dca89fce402fd0ea27f5a6effc82d
bfb8fc7557
EvaluationElement = 03085806170058c5189010e315013a68259e862c08e6ef21
c40b9068dabc4187f611a303c57db80cdc3d9b4e537fcda75c,02936ab564ff79eea
ff16c3fdc176ba71c5351d60ec067daca44b7ebb3c106439ac0aaecaf9f8974a8326
90b8e17907150
UnblindedElement = 03f76b2ddddcce5db5504f77d07eeccd8302436818c4882b2
93499f31255b139aa3ed920002dc2e201b725de580b251852,0330d4bfdc5dab25ed
4813570b4975b16a6fd0202bb2373a00edcb008ac105f51216837973cd29f20744ea
c13619ce28a2
EvaluationProofC = 37de36448a3838fc074c4eb87e1dcda24d80cd8e90ebf778f
1e6c22a14e87e76691271324e656319cb572c2cf38906a1
EvaluationProofS = 89512f46b3282d5cc3cfc816f13ff6213ae66eb97316fcbb8
b1196e50708f3dead470f6913cc7b5bc4655f8a54aacbb4
Info = 736f6d655f696e666f
Output = 5dba66546a633215df3fb6dc002655f43ed07f497fd1b4ee6f2214fd657
8aebbceabfb3ce03ce005f0f457b6764e74dfa78d72ee5cc21e167a17c67ce86847e
3,558a6bcecaab839fe9a7020352655cd79ddca1c7c29ac1f062a4a96a69b59fd3b3
85a11481f6fb4c2d8900d1c6897b5d5a6b14c2bd31dc7282d643b9630529ad
~~~

## OPRF(P-521, SHA-512)

### Base Mode

~~~
skSm = 01b68fade716a6a82d600444b26de335ba38cf092d80c7cf2cb55388d8995
15238094c800bdd9c65f71780ba85f5ae9b4703e17e559ca3ccd1944f9a70536c175
f12
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 00dd0772f68b53baade9962d164565d8c0e3a1ba1a337759061965a423d9
d3d6e1e1006dc8984ad28a4c93ecfc36fc2171046b3c4284855cfa2434ed98db9e68
a598
BlindedElement = 0200c90f3a3d634131d2c6c28fb3c68cd4a2fcf645e02bf5dda
da3cd3400fe1a9b11c8149f74e97f305c6bbed99e4bf1d0e4e15648db2f7ca4d377f
d5e063767d8b878
EvaluationElement = 02015d9c192d77d428e77486ba09239c9e9666e3de62d578
7cade4d92e9017993607041fade15f90d8f6b45847b5f5a2c5355d7aa8696aa2a8a4
aef3b1f565c3c8010e
UnblindedElement = 03005e3cef397da7e8d193d31107ea2da163eca97b54d6d6e
cd664b9c5021834f355800657bbde325f9c4c5a5a64d5a7651d669b720e46674e069
14382182dcce16fc7
Info = 736f6d655f696e666f
Output = 0f742a304c09e4d3548a16417776b8164a2adb5aada68966e4f6f216d9d
1c89465f0ebc01d81a2ed2243637e3f0730e705c752be32b414d4e8b056b5dccc928
0
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 00e8bea293aa8a69353b023f4a0e6a39eef47b0d4ca4c64825ba085de242
042b84d9ebe3b2e9de07678ff96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd
1fa8
BlindedElement = 02013e9e1424ad951f402f53dfea37908bba1e03bcb39984803
6620779fd2cab5d2d300e78600fcd256cb2d14ccaea3864561d848d561785ddabb3b
01b27155aae312a
EvaluationElement = 02014ccf9eeefaca351b8ddebe68b2682c98279a5222fe74
0cff6be1cd85c349bdea0e8be5bdb0e25ffa56f222076eaa823a625354809e34b08c
a8e7e7afd8465cfb14
UnblindedElement = 0301938d6f170ce442b762cf25f9d816d22d3ab10f4416aa0
6ee061aef19954a1a13b3910d243b3fe046e54cf19d16191d55230b92b4d0a004bff
74087453425630e1f
Info = 736f6d655f696e666f
Output = 30d3e2dd8385e2e814a22f36e1edb66034055c99a044745603e32b0f1f4
f743a62a4b98f44b9587521a9387bfd428166db97b433246a7e1a572c29e3729d1c3
7
~~~

### Verifiable Mode

~~~
skSm = 01449bb3b4ef3d5c65b55a1b8960563b3420d7764097502850c445ccd86e2
d20d7e4ec77617a4238835743037876080d2e3e27bc3ce7b5fb6a1107ffedeaedb37
177
pkSm = 02010dc16a63cb3e75fb306038b8364f55a1fff4e168538c4667cb1511260
ecae34fe14916ca1d19a0f2e208f537ae634751a9b85d80b33e9c02563de40c86d13
47679
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 0086b18e24c9a40ed5eec262bf51dc970d63acb5ab74318e54223c759e97
47f59c0d4ecbc087302667fabefa647b1766accb7c82a46aa3fc6caecbb9e935f0bf
b00f
BlindedElement = 03007023e7afe67d3c5a912bdc703e11822e3d72519a7724139
1958603e5356029f8a5ad66a71dd14054ffe6f5b5c5055a151dfcbaf36784c2cec4a
c3802681982afe2
EvaluationElement = 0301286ee7068eca78bff9786df0deba99abd288058f41fa
d91ba57cb5e946f37da2fb2486c70cc1570230b04b97fa1e732ff898ca032bb0fb11
955b70a226715368d5
UnblindedElement = 02006ff10e5a67d2f1b7dd74e5b3d927478b25eecd1cdf068
139f30dc269f9dc31805b0ef8f2481b922b3b8e90a7a821b3cdb5e0cb4ae4d64eac7
35693038b6cc4503e
EvaluationProofC = 01bff02b0ea6c9501a91d3a84f3a91c582f9216974a981efb
f5c7f7002ad96746a5d72a8430de6f69c22c2d2dc2ba69cc739990eef75b0daf90a2
c5f069569cd3974
EvaluationProofS = 01a08833077d1aec89a730429e8062e71bd085a1dbfaa7f68
953cbf3af5e05dffa7e040db2ee81c1b1f75d8d5d9015ea0fae55f10968c1577aa0e
38e718c4fc8ff80
Info = 736f6d655f696e666f
Output = 5670e106e2d41747c7b1ac1902818022fe3019062f2cbe57810d21be5ca
d0abf32093be1b3db99dc49ce5d2b39c4667a88a397dedff2068286c49f2c11f2b5e
d
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 00b9f3ad744eb5baf418275e45ab31ade30669dbae98fb0879524fb9234e
93a8bd048ad9f44b428026396a810328c405a354e666f086fa0ea4754fb56527be01
0297
BlindedElement = 0200df8a5b7753f5a6a640e6db207649cb07e3a76931a40e9c4
0e54dce933c26f0450461b2885eab5a202485ba35ae2ff006964b88af4069b68b9c1
554c3e940e0b943
EvaluationElement = 0200736c0d07ce6ccda8f0a8e31218ed844f7729c9943881
1f0d91a3cab6b0cde7b726cd65f9622e757d06bd8dad2894601e1635b3d345193a7c
e47e2d58b5bfb5ffa3
UnblindedElement = 02001f091d698d71ab48a00104ef005dd1feb85ca48bc5d11
3c9e6c2df3f079b8888d1ef24e0bfee75d90c712bc5d7ecd655b32cb7f0259654bac
bf9766801ecc9a29f
EvaluationProofC = 019090a83fd579e254811a733469eaf9163efa8397bf61d54
bc9f0b3d919e2e92ffddcdf8639bbad1cd9696d9f568452eef1ced4a3861af505dcd
af6321c7b3a069d
EvaluationProofS = 00532d796210ea9e5eea285d358c8fdb4a1e8bc7559389276
5e13db6f64a52830fa2c55a1e5039f4aeea2309bdb1bb55f964113d4b25fd169cb91
fd93dce6afd6199
Info = 736f6d655f696e666f
Output = d9ee7a801a46c8c5c69c11340073b56f6ed4bec7a2b31b6e6776246beb9
717f37c966f3e98f2156a3905f8c4ddc3740afaa653333718c37e46b5d06e4570d7b
0
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 01daf5685928c72d9dab8ddfe45de734ce0d4ff5823d2e40c4fcf880e9a8
272b46eea593b1095e7d38ba6ff37c42b3c4859761247a74d0c62c98ddff1365bb9b
82b3,00b96540574e2bc92534ac475d6a3649f3e9cdf20a7e882066be571714f5db0
73555bc1bfebe1d50a04fd6656a439cf465109653bf8e484c01c5f8516f98f3159b4
0
BlindedElement = 0300d45e787f24a39c52cc290f0b202c03d320b1213a9dd4429
df6b7f455a954b85815b5b379db5b4b9d665abaaf26366c91b8cd4884a2cddbf5be0
7420726de773fb7,030122ca1ad84feb6dc2832373011608a6d7f7f8e632c66cc6e1
34de50aa4317caa9c9b11cb281ae7dea4286a7c217cb9937d470f28a8c800dce277a
759342dd9a3e0d
EvaluationElement = 0301d8af9135b69b174238acd802e31323e84f9f66c7d3ca
68659ccd4456f16af156c15d48c8d7003f64fc8d814d09e5e4f0bf54dfd719ddaf10
19f667ea0f9e58afed,0300e253175c05483e6696eb6447f4e3ae87c0764909749a6
4c902dbe11a8d575e59d13c86f499483f99d707d5485ca441e48cc9e0f78fbb22225
b91c8870f8d094aae
UnblindedElement = 02006ff10e5a67d2f1b7dd74e5b3d927478b25eecd1cdf068
139f30dc269f9dc31805b0ef8f2481b922b3b8e90a7a821b3cdb5e0cb4ae4d64eac7
35693038b6cc4503e,02001f091d698d71ab48a00104ef005dd1feb85ca48bc5d113
c9e6c2df3f079b8888d1ef24e0bfee75d90c712bc5d7ecd655b32cb7f0259654bacb
f9766801ecc9a29f
EvaluationProofC = 00ef808190325fb49195e5244c1477694ef2770626369dd0a
d0a428a0482ae69b837ff8e9d34e347ee8bf5e6a30d6ef7b9c8e995ef3aca5a45218
c5ff97cf4bade00
EvaluationProofS = 01b7c17f5474a7fdd637e6351566b7606e1b03ac034728e24
5a855278bc245fe2d1fb6c93180b4904f1037909d2ea8746ac806e507b7de668cc13
0de7264da4003e2
Info = 736f6d655f696e666f
Output = 5670e106e2d41747c7b1ac1902818022fe3019062f2cbe57810d21be5ca
d0abf32093be1b3db99dc49ce5d2b39c4667a88a397dedff2068286c49f2c11f2b5e
d,d9ee7a801a46c8c5c69c11340073b56f6ed4bec7a2b31b6e6776246beb9717f37c
966f3e98f2156a3905f8c4ddc3740afaa653333718c37e46b5d06e4570d7b0
~~~
