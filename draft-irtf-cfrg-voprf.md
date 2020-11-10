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
  (See {{ciphersuites}} for these base base points.)
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
for advice corresponding to implementation of this interface for
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
    using Order() as the prime modulus, with L=48, and expand_message_xmd with
    SHA-512.
  - Serialization: Serialization converts group elements to 32-byte strings
    using the 'Encode' function from {{!RISTRETTO}}. Deserialization converts
    32-byte strings to group elements using the 'Decode' function from {{!RISTRETTO}}.
- Hash: SHA-512
- ID: 0x0001

## OPRF(decaf448, SHA-512)

- Group: decaf448 {{!RISTRETTO}}
  - HashToGroup(): hash_to_decaf448
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions, and `expand_message` = `expand_message_xmd`
    using SHA-512.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L=84, and `expand_message_xmd` with
    SHA-512.
  - Serialization: Serialization converts group elements to 56-byte strings
    using the 'Encode' function from {{!RISTRETTO}}. Deserialization converts
    56-byte strings to group elements using the 'Decode' function from {{!RISTRETTO}}.
- Hash: SHA-512
- ID: 0x0002

## OPRF(P-256, SHA-256)

- Group: P-256 (secp256r1) {{x9.62}}
  - HashToGroup(): P256_XMD:SHA-256_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L=48, and `expand_message_xmd` with
    SHA-256.
  - Serialization: The compressed point encoding for the curve {{SEC1}}
    consisting of 33 bytes.
- Hash: SHA-256
- ID: 0x0003

## OPRF(P-384, SHA-512)

- Group: P-384 (secp384r1) {{x9.62}}
  - HashToGroup(): P384_XMD:SHA-512_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L=72, and `expand_message_xmd` with
    SHA-512.
  - Serialization: The compressed point encoding for the curve {{SEC1}}
    consisting of 49 bytes.
- Hash: SHA-512
- ID: 0x0004

## OPRF(P-521, SHA-512)

- Group: P-521 (secp521r1) {{x9.62}}
  - HashToGroup(): P521_XMD:SHA-512_SSWU_RO\_
    {{!I-D.irtf-cfrg-hash-to-curve}} with DST =
    "VOPRF06-HashToGroup-" || contextString, where contextString is that which is
    computed in the Setup functions.
  - HashToScalar(): Use hash_to_field from {{!I-D.irtf-cfrg-hash-to-curve}}
    using Order() as the prime modulus, with L=98, and `expand_message_xmd` with
    SHA-512.
  - Serialization: The compressed point encoding for the curve {{SEC1}}
    consisting of 67 bytes.
- Hash: SHA-512
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

Consequently the cryptographic security of our construction is based on
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
client that submit Q queries to the OPRF can use the aforementioned
attacks to reduce security of the group instantiation by log_2(Q) bits.

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

For some applications, it may be desirable for server to bind tokens to
certain parameters, e.g., protocol versions, ciphersuites, etc. To
accomplish this, server should use a distinct scalar for each parameter
combination. Upon redemption of a token T from the client, server can
later verify that T was generated using the scalar associated with the
corresponding parameters.

# Acknowledgements

This document resulted from the work of the Privacy Pass team
{{PrivacyPass}}. The authors would also like to acknowledge helpful
conversations with Hugo Krawczyk. Eli-Shaoul Khedouri provided
additional review and comments on key consistency. Daniel Bourdrez,
Tatiana Bradley, Sofía Celi, Frank Denis, and Bas Westerbaan also
provided helpful input and contributions on the document.

--- back

# Test Vectors

This section includes test vectors for the VOPRF protocol specified
in this document. For each ciphersuite specified in {{ciphersuites}},
there is a set of test vectors for the protocol when run in the base
mode and verifiable mode. Each test vector lists the batch size for
the evaluation. Each test vector value is encoded as a hexadecimal
string. The label for each test vector value is described below.

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
"Blind", "BlindedElement", "EvaluationElement", "UnblindedElement",
and "Output" fields.

The server key material, pkSm and skSm, are listed under the mode for
each ciphersuite. Both pkSm and skSm are the serialized values of
pkS and skS, respectively, as used in the protocol.

## OPRF(ristretto255, SHA-512)

### Base Mode

skSm = 0x38ecf12e5465e4f1362d237521104338cde6717e26a25a5770da7ad85c7
04c6

#### Test Vector 1, Batch Size 1

Input = 0x00
Blind = 0xbe537e02b0116a48941a76d08b3af2366cc6ee4237b306d3153fc6b209
5d85e
BlindedElement = 0x648a5a3508aa41c32b119bf6da0199f5dedf44e622e426412
991a6660cabcf36
EvaluationElement = 0xfc34c9332576963b9a2c5a4afacb78cb440eedce98dfa4
4d12fc5f7a9d223a19
UnblindedElement = 0xc4d9a44269ec66e8332471b92f37081207ebca061beb4df
621a309fce23c8809
Info = 0x736f6d655f696e666f
Output = 0x00999fd3f5ddd9bd1574226729749cb19c8a6060fb231e1e573ab1543
9c19270d981936e8710cdb9df3f4d59243936c606d73dc5dc12b827f7bf084ff2b27
5fc

#### Test Vector 2, Batch Size 1

Input = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0x33526e3638d51e7645a0ec1e9afdfaa431e0627b7ac461f5dd0b1b6fe6
683ed
BlindedElement = 0x62beacd596ce27a45399522bb8edb69f3e9dbd3478bca8b37
0d801758a301667
EvaluationElement = 0x625bc0952c4c345772c8cf268d930a724a728c0117f77a
c8151df322eb55357f
UnblindedElement = 0xcc3f3888d4abc0420e959bed3d4be03f88d38d262da8208
1df9cb639cd04776a
Info = 0x736f6d655f696e666f
Output = 0x28c9fbd38d6b3b366a6cec64ca622600ad4928e6860e4a645b0c926eb
1168bd35280e4a84a20b333b1e329113ce9cc477b25c0f2743ccd52020db0d1c2c40
28d

### Verifiable Mode

skSm = 0x91a688c1b83ecbc9dac5da9042f60bbda9f332fd6cdf828252920741dbd
9c01
pkSm = 0xeee7a9c7fec3460c27c160c683d46a4fd18f537c055c3998748b8e4cd8f
29b3e

#### Test Vector 1, Batch Size 1

Input = 0x00
Blind = 0x7e7b0d8e0e019c1c5e47d3b1743cf3b333d8459e92f1fa45c1a19c8421
ac689
BlindedElement = 0xb00cd0b3bf341fd7b2dc1c22d569a05baf59578043f2e46c8
471a5eb72775b65
EvaluationElement = 0xe6b9f6255bcd1a264bf88d3e5c1c163d2df374f6f6c82b
e3999fdf8fb6734074
UnblindedElement = 0x706e886d7ac87e6081b58bc85dfa05a7e513dcccec61477
54614a466c0def010
EvaluationProofC = 0xf8a6e21a226cb7da4ccbbdb57267b60c2fa84c456e09512
bd7452ccf5909077
EvaluationProofS = 0x663bf1bfa8bda78cc632907bf26923393458d966bab8ec4
081fb8147c12d201
Info = 0x736f6d655f696e666f
Output = 0x1985127b2de75760e0af95961579906359dccf9a76b18aad8ed036dec
48e51baca318d301bed3b0401ba6dc9a8410c7977b82c034e4137416b08130810ca1
614

#### Test Vector 2, Batch Size 1

Input = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0x9c97062a1b0a0229b0775217c99815e2036aff826a4044cb752ade9225
0668d
BlindedElement = 0xe8c58b5dc65f2ac254f6f71c2708e25f004eb25c850a48520
6569a3686030a37
EvaluationElement = 0x5629e40ddefd92771893d4485aeec7c39a23a50dff11c0
7ec6eb1dc01a285c29
UnblindedElement = 0x70cfa3bf546b5f93c44cccd5e23bf2b9c0d30b059673303
94e99d02ecbc71860
EvaluationProofC = 0x999be3a7cd614160b46b0702b6f8838019e16ad0766f9f3
43118c361412e74a
EvaluationProofS = 0xbf542c9e39dc935c3e147ecf6ff0ba27e677f506e415a63
1a9deda88ac0c81d
Info = 0x736f6d655f696e666f
Output = 0x0e2161ddb74dafd8165f597b775686ac62d43463b5b20021acc4af672
e2abd7993f0cf92d6b8c66c322ab57a5b1c137015a6c99059af8ef581ab75c551aab
eee

#### Test Vector 3, Batch Size 2

Input = 0x00,0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0x8ce6d88376170a98651af33ac718e4c44f8220586a8e4ee92157925c3a
ef53a,0x4afef5d250bf7f992b0e07477e3d32487b2d637e712ef4ee28dc1da700bc
b8b
BlindedElement = 0x7ac963d8a1e4f68a66e14e1b3fa84406719e16aeb0ec9d1ea
ba867a939c2d671,0xcae915c223a3da7bee552b9eea2c8d9d8ce9ac56b41910e1ae
f75af555724f4f
EvaluationElement = 0x822196a47d3eb43d1763c459b78d07c775d1fa1314be7a
d4f381f1232fc49a34,0x9467a38af4e1b7875ebfda1dd345207dd59c6c4cb163c82
46f46aa736b9ec234
UnblindedElement = 0x706e886d7ac87e6081b58bc85dfa05a7e513dcccec61477
54614a466c0def010,0x70cfa3bf546b5f93c44cccd5e23bf2b9c0d30b0596733039
4e99d02ecbc71860
EvaluationProofC = 0x44a3f86ad905dd37f4fdbf9f69d483dd80fe20740705ab6
f996b09e332afc89
EvaluationProofS = 0x486836dcab5b218775aa5b27a5ed7a78325fb223c69549a
922569a9fc738fee
Info = 0x736f6d655f696e666f
Output = 0x1985127b2de75760e0af95961579906359dccf9a76b18aad8ed036dec
48e51baca318d301bed3b0401ba6dc9a8410c7977b82c034e4137416b08130810ca1
614,0x0e2161ddb74dafd8165f597b775686ac62d43463b5b20021acc4af672e2abd
7993f0cf92d6b8c66c322ab57a5b1c137015a6c99059af8ef581ab75c551aabeee

## OPRF(decaf448, SHA-512)

### Base Mode

skSm = 0x2ca920ef55992e2ee92317a26274bde189712cce3955d9f6329eea5c98a
24d7ee5b56a88a373455e579f77ec5404344e35fc5f0d5fa1d5c4

#### Test Vector 1, Batch Size 1

Input = 0x00
Blind = 0x3c58ab1fdaf719be997bbf22f4982eddffa371fab8dcfa66f1a4f80542
c3fe50d9dd39f68aa5ef9bed0ba57d4788728bad4f8d61d3eb4358
BlindedElement = 0x84be45bb776f8f15e8ed716663a010773cb44ad3b2c4dc669
48c2972bac99913308f160737e3f32a44349584a4b6ef4adf924f5fcc192d17
EvaluationElement = 0xa6cf272ceb18e8f6abcf9216819b0b2265ad10502633d0
871b102b5ea7f574d9c6852af32f1082b578878bd09709df1897aa064f52b16414
UnblindedElement = 0x0cedeea1ef6934cff2d95b2af842806d7364312d8845504
ae31dac84511a92285d20cb281e13797f37b4415f117915106b9bf3a0a462eee9
Info = 0x736f6d655f696e666f
Output = 0xe0409c1eaa2cb3166cb4f8799c8b8054fc30139caf3339ac541438af1
17a0a6f7a03db76fa83aaa84a5ce8145341fb707bf06b2e9aa027b5613a7ddb09f3f
c7b

#### Test Vector 2, Batch Size 1

Input = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0x1df1a73c78b54b606155a520b6b285f63244a7720e3e13d960bc62e56f
f37c6581f2fc4caa02d0c319008799af0a9a144063ec25a2359d5a
BlindedElement = 0xf0d1f1eb43b85e6dde38c0526151db3745b672667bef97bb0
a3553e191ad47f8c04e4a4c1588f028afecc170f15baeea2d44e86fe67982f8
EvaluationElement = 0xf60cf47549fa62e72ae7253a4d42a8fc6ca70e0ac0ddc3
1930627692eb3096792cf988115f792c99c03b08b0a5d07f2a2b7141dcb8c73cb9
UnblindedElement = 0xa8d2cfdb49a2d1409a53656cbdf12829ccb6fcad7380772
7dc2eaa4499e45f0af4cce88b443bedfc4cd08e9cdede61fd243e089a4f010a0f
Info = 0x736f6d655f696e666f
Output = 0xeda4b68203b190cf690214f6068d174d795406a106bbe07f8a20fd66a
8342bb2a31a49739b593544601039613be85900f4ae79711e8a706c2a74174d4c867
7b2

### Verifiable Mode

skSm = 0x2ddf6a2f6050114b35e95e4a658ed5e1c672df059de9473a310eac1ec42
5a4d26da4096a158435c1637b37f920e097394139483eea7a9eeb
pkSm = 0x3ae16a2f8c506ebef74fafa9190e19447b07772e3077300b758411b941d
8d61f6b1840b35a73578f6aeb09e1a302a9d68f1db1cb34e90014

#### Test Vector 1, Batch Size 1

Input = 0x00
Blind = 0x71ab3d289f114a55fd6bca1cc98ead4b590ef189459b62ba67d1b0154e
9ab86130ef1033f55aba050095b231b227acb849f55b8cb003ed8
BlindedElement = 0x54c5fd05a11cd041f09a80db5e8a327b654d24563178b25a1
28b549d32857167062e3ba259de5e938e3635af9d17fdb3cc38fe43d21951b5
EvaluationElement = 0x5e284dc6fecae55bb6263a03ca772979ea559b28c8ba31
6d4fe3e8c6c38649455982f31f84679aa5db3264613671ab238a9950a28b5d6471
UnblindedElement = 0x62a06f98dd6e56123081d519d3926ef6a0b3dd02659ec47
0bf60ad2bdab709fe11d88e74168d1110245cda7ad654340ea2430ca86974e166
EvaluationProofC = 0x3dfee5d8c683113cad6d19bde0d47642db146c1212d226d
6cc7ab67461f0580b924a81cbfaf497ba91dbfd89f7bc88c293a75cc4ab97afc4
EvaluationProofS = 0x1d841a418b34ae50ee515c11598835857b69dce2a7724d5
04db6af5e8768b5c11801cc05f1fbb782dbbcbf95a157ac57b69a67bddad264c6
Info = 0x736f6d655f696e666f
Output = 0x77e96be0813c333a233518fe87dc845b5b58944e428a64c1489e04a15
f4128a818198fcd65195a8435717ab6a87815bfb8fd220ee9869c9b6e6ea00b7840c
1bf

#### Test Vector 2, Batch Size 1

Input = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0x16eafca7c98af0cfab51fd7202017f0377bf4cf8a378c46175141eeb28
db81bd6e67ffd9f8af813a48c2c5f724dc590126da289237c586ec
BlindedElement = 0x9ca39b9c495b8fb1824923cd4b564a37e3921c7c6eeb799d4
489038f8b24388e858e67a461b776318eeb7fc1c59eb7e3f32b341a5b5d2308
EvaluationElement = 0xecf902b012dbd2cdf5de49ca99e2251948c93d345f7d4a
6d42b5ea5cd321ccdded0f89cfd63b3c77afe22924924814299e595a8656c2f56b
UnblindedElement = 0xba5084a399f858f5e43c959f207ce4707d63e921d82f1dc
9caadb4361b56953c63ea8d41baadbf2d0ba63ab490cbcc8856d9d53e46efc7d4
EvaluationProofC = 0x343976ba20779299c71bc8354f19d81be4f1e89c5da8322
03f7e671846297243046d9e3629489f16e762a306cb7b3977f680b7ce322667d5
EvaluationProofS = 0x141af1ff9612f4f47ec8beb8484aabe633af02137e73c6a
9369d53f6d79ba9ffbd0d8c49d5dda82a5bcc9194beb1586ecf01ba01f2b64dbf
Info = 0x736f6d655f696e666f
Output = 0x63c9aad6d56f8ec8de915a742c8543202837bdba0350770511049bf0b
546b1adffac5ca550c15ed0f94b89053a61a6ff52df629b8f91793b489b547bf5b95
662

#### Test Vector 3, Batch Size 2

Input = 0x00,0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0x3f0b9c562db1e7a3ad4ff8af1b24daa1922d13757ac9df4adc7e4e0b6b
39943267b5bcebad6393e2d0b7db3d2b4597a670a5204b2b606f5b,0x189aa4e719d
aca653b9217801b5d51cef66d9fdbd94a53533e7c5057e09e220065ea8c257c0dd60
55c4b401063eff0bf242b4cd534a79bad
BlindedElement = 0xae30869b3292b406ffae15145f8d056232cc6c6b6ea9d4900
4fd3a2492aa2770e28b0ee344ad438180deacf501ec54cae7c1f8b0c4e6958b,0x54
fbd37ead128577c7536a862d018b29c3dbc9da09e6cbb9d7a96013b6ac8f9d0b1599
cfd59292ea9ef95240c9e8796b41e49b3037b4984c
EvaluationElement = 0x92fe4293f5dad22e44e91659b20ee0e5fdf5f805d9148e
e49573081aea607cf9e05ce16c802cf76db06b3f95d40175829c2950fd5ad1a82d,0
xe60a930f90ab1eca807b057200fb997c68808aab811cbde365451f86c4132684e61
3410b00f39b7f080fd37ed4149cf3df5e7152ff8004b1
UnblindedElement = 0x62a06f98dd6e56123081d519d3926ef6a0b3dd02659ec47
0bf60ad2bdab709fe11d88e74168d1110245cda7ad654340ea2430ca86974e166,0x
ba5084a399f858f5e43c959f207ce4707d63e921d82f1dc9caadb4361b56953c63ea
8d41baadbf2d0ba63ab490cbcc8856d9d53e46efc7d4
EvaluationProofC = 0x1e4c00f21f788c4f9ac47859ad57e0483e96935e8d7e69b
64bb94702ee966697822d40761d29e093b8690cbbc60707c49f6df607dea5dbe9
EvaluationProofS = 0x219ae5ebd7e2d022549a290c8333f97d5cee7d35c379993
b2f193c4b73a312d11a51d67f5cce0b90e807e86ac0bf6625d707184a7127129d
Info = 0x736f6d655f696e666f
Output = 0x77e96be0813c333a233518fe87dc845b5b58944e428a64c1489e04a15
f4128a818198fcd65195a8435717ab6a87815bfb8fd220ee9869c9b6e6ea00b7840c
1bf,0x63c9aad6d56f8ec8de915a742c8543202837bdba0350770511049bf0b546b1
adffac5ca550c15ed0f94b89053a61a6ff52df629b8f91793b489b547bf5b95662

## OPRF(P-256, SHA-256)

### Base Mode

skSm = 0x2902c13bdc9993d3717bda68fc080b9802ae4effd5dc972d9f9fb3bbbf1
06ade

#### Test Vector 1, Batch Size 1

Input = 0x00
Blind = 0x359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7
b0df39
BlindedElement = 0x03774b90bbb29af011e08dcb31ec7aa5f902afe02338f96d6
b817400f7d77d987f
EvaluationElement = 0x02350c80b07aa03da012f7d9162645673bd3535a89b96b
f52f4f0d9b026610b325
UnblindedElement = 0x036421a5471d3efcdd941dd85b511939ffbee330d8c96ac
5e1a529cc428eab3aeb
Info = 0x736f6d655f696e666f
Output = 0xabd0a95b0fd52a26ef367199b96071b8a3d40c4b403a8b97fc5b567f2
7fb080d

#### Test Vector 2, Batch Size 1

Input = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0xb5e8f3c63b86ae88d9ce0530b01cb1c23382c7ec9bdd6e75898e4877d8
e2bc17
BlindedElement = 0x03ec4301d1d42a4582588a9258413a28cd997de3468e198f4
63eadbffcc2adeaa5
EvaluationElement = 0x03807af5cbdbf6c56842f866b87c69f7b9fc4ab8d89135
3df97395f63145c9aea2
UnblindedElement = 0x03bbf0692f18ec393df3755ae5fcf0473ba4c924fc32dd1
1840dd196bdf15471c0
Info = 0x736f6d655f696e666f
Output = 0x9f2ff595e24982d3e8338a596783b673e71620d9319f55817742933a8
9c7ff55

### Verifiable Mode

skSm = 0x4283efb9cd1ee4061c6bf884e60a877321ece4f9b6ffd01ce8208254541
3bd9c
pkSm = 0x03c335d2eebd0ccbd5b8a145c9c2ee7452f401dcd4301ab138b0b56fc1c
72769cb

#### Test Vector 1, Batch Size 1

Input = 0x00
Blind = 0x102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b
09589f
BlindedElement = 0x024829172675a0f6036657cd5d9eb0cfb97cad2eae79dfe51
66095d4db0fe4a49c
EvaluationElement = 0x02fef714dc9464983baca86fee8857a6afec020a9ea944
0d31f141c5957e04f494
UnblindedElement = 0x03e0d6dcbce22e122a441c27828bf5867ae91ef0287af66
2e24f47b31e2bc92ae2
EvaluationProofC = 0x2d0c60ea2211b48ef1c3924d5243fe81a1c9155c6578af0
8e664565d3816ac6a
EvaluationProofS = 0x74d637aa4522b51dcee362a9ed306b6b8a54727f7b4e5ab
8c3b3e1c6e5ce02c
Info = 0x736f6d655f696e666f
Output = 0x25820403dd3523604618258da6a41a6729a8d0a83dbafb6f579d1d4dc
b2edaa3

#### Test Vector 2, Batch Size 1

Input = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0x76f08753056c186437ded8ee22f96e44bd5b6ec07cb131d51cf1324c12
38699
BlindedElement = 0x03de136afec7e193e73d28d83e84a2b31b4532da77b8ee9a0
53ad209873e3841cb
EvaluationElement = 0x03e2ce505dcac913ed1e29c1dd34cc3e3079887ee57754
201e0642ede25538e27e
UnblindedElement = 0x037dd1c0daf493d8a2ab3a2b4fe2528caec6aba63d0a483
032860abf8bd8ea74f3
EvaluationProofC = 0x238f041989e3e71ff5ee25e86566c76e4366baa819bbfbf
bc4757cdd2f3fc6d5
EvaluationProofS = 0x766c01412f32e6740972e4b5fda0563e3720faecdd4aaed
ebba0bba84248aa04
Info = 0x736f6d655f696e666f
Output = 0x6683239f5e1c611d775fe9c73014bc832fc966c5009e268fb955c9bf9
74abb58

#### Test Vector 3, Batch Size 2

Input = 0x00,0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0xbb1876a7f7165ac7ec79bfd5213ea2e374252f29a6e19915f81b0c7dce
a93ce7,0xe04f47e8d2554a5ebd83679b4c1e67ed82f2891751aa7094602be672c32
4929b
BlindedElement = 0x0245a57f9e991bb3661c3343772cdb16cc16217d441e0847c
7d4ae8eaad41a980f,0x0375e7898d32f42e0479a8bd7017378604df8d3eddee91f3
a5e70df7126fe8050d
EvaluationElement = 0x030eb61d8599b8703ae0cd1c5b988d4dc9bf77645c2ce9
b50f6e8bcee1149cd5a5,0x03f6055d4cb2471940ed0ee2b647a0cf89a283484c29f
ebbf2d49a7d77e7f23c4c
UnblindedElement = 0x03e0d6dcbce22e122a441c27828bf5867ae91ef0287af66
2e24f47b31e2bc92ae2,0x037dd1c0daf493d8a2ab3a2b4fe2528caec6aba63d0a48
3032860abf8bd8ea74f3
EvaluationProofC = 0xffeb7a787565a5d23f0b3b5c2c6064ee1d0aa69e98f7bbe
047c14a7b924f11f3
EvaluationProofS = 0xf8c99cb8557db8f77509a041a5fb9bf7df9d50e538cb68b
ba59adefc7b4a6985
Info = 0x736f6d655f696e666f
Output = 0x25820403dd3523604618258da6a41a6729a8d0a83dbafb6f579d1d4dc
b2edaa3,0x6683239f5e1c611d775fe9c73014bc832fc966c5009e268fb955c9bf97
4abb58

## OPRF(P-384, SHA-512)

### Base Mode

skSm = 0x6cc9faa9dc7ab251997738a3a232f352c2059c25684e6ccea420f8d0c79
3f9f51171628f1d28bb7402ca4aea6465e27

#### Test Vector 1, Batch Size 1

Input = 0x00
Blind = 0xae86286729214a1ba9a359ab01833477b8cb91932d0c81667a0e3244b8
96ac141b538ff23749be19e92df82df1acd3f7
BlindedElement = 0x0256ec771e8a7b770ff9ab40efb499279ed9a71d36ab6bc7d
40cd64565c66c2db285b8fe58f47e68bf3c02b98c90684aaa
EvaluationElement = 0x02bdf50a96769acb293d3ba11a124c6b784e921d2d3d31
12eb696a998a0a3464c9c27f6eddf8a270ac721678e75e7df344
UnblindedElement = 0x0339cc6aa5b5ef9bd0ba57b1f317e17d8aac3311c1fd6e5
81ae84b4af19f4d4efd2877a8e127a7141cbedbbebd77826192
Info = 0x736f6d655f696e666f
Output = 0xfd1266a98b2b0ca3971fa82295f1893a548088aa7bd500afa915f0745
b89b1f94a6f4c08a68e8a79a0cc958f81d7c2badfd797509d7b987ca295b91a9786b
914

#### Test Vector 2, Batch Size 1

Input = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0x523eff8db014d9b8b53ad7b0e149b0938b45f65717a40c38f671d326e1
96e8a21bf6cfd40327a95f1ccfc82a9f83a75e
BlindedElement = 0x03a4badb8d617e78f7df557e183d01e1284920f5e84bc916b
4185b20f57129a09a301e57d4ea93463f398c31b52934e91c
EvaluationElement = 0x029fffdcadf404bec3ac2a120a0e4df38c6563e691cd25
6c6fe6adaabb0362097b6026ae3c6e2995cf5f0c18548e6706af
UnblindedElement = 0x035540b79d5a64cb696cf0310692cbadd391d5de2f19f83
8b17264d5117a0813489c9a28a604e3ed56b00aeb5931391cb1
Info = 0x736f6d655f696e666f
Output = 0x94ae0bd412a7b5cf1318f530d8434c9c64ddceed221fab1a958f0f6ee
18fe598b2fb51c65d3d2e1aa5ff724e718e0b62178dbd4019bdf051b7edc8c71dcd9
151

### Verifiable Mode

skSm = 0x32370deb7c3c17d9fc7cb4e0ce646e04e42d638e0fa7a434ed340772a8b
5d6253d35895f4cff282d86b2358d89a82ee7
pkSm = 0x023112a158597bf66974ec2391209063aa489fc1e98fec51be3a81aeeac
03b94dea1deee98515dc73c060a1432913d1a5d

#### Test Vector 1, Batch Size 1

Input = 0x00
Blind = 0xbbabe8add48bcd149ff3b840dc8a5d2483705fcc9a39607288b935b079
7ac6b3c4b2e848823ac9ae16b3a3b5816be035
BlindedElement = 0x0255b8e051b51b644548304894e2f41b012075a807d5dc271
697322cc057e19834c6f47e24309e2e102e44c92c321694a0
EvaluationElement = 0x03fbffe94ed4b87bbee72fbdc3d7698bc7f9e39af32a16
12ba1c4c2d626678754c0675644a67d7a9e6fdcb2da882018328
UnblindedElement = 0x03f76b2ddddcce5db5504f77d07eeccd8302436818c4882
b293499f31255b139aa3ed920002dc2e201b725de580b251852
EvaluationProofC = 0x9bc67e891fcd80112dfe7deb70182bebe509b470fe0f194
a03d16cdcdb2a3a8008ec19ba26366ca6bb8809af6a44e7e0
EvaluationProofS = 0x73a2a536c65b6fff02eb9615d7c08490f3d0cedf789a6d7
91cb3b98592f5e1941fa92746fb73f186b534e27b540e0c2c
Info = 0x736f6d655f696e666f
Output = 0x5dba66546a633215df3fb6dc002655f43ed07f497fd1b4ee6f2214fd6
578aebbceabfb3ce03ce005f0f457b6764e74dfa78d72ee5cc21e167a17c67ce8684
7e3

#### Test Vector 2, Batch Size 1

Input = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0x470f06169bee12cf47965b72a59946ca387966f5d8331eab82117c88bb
d91b8954e16c0b9ceed3ce992b198be1ebfbb
BlindedElement = 0x0358930b1c57b54bf884d0b76904f11a4a139935e94ddc552
87678f041e9a9dc1f435a68f74df8c9d5febd1a4d910ad9fa
EvaluationElement = 0x02636fea7f2b916749f2eab123a9eff087688d8e5a7c2d
95df91b6defe1e0180c5272c9866ae95ad9697ae96c70967cc84
UnblindedElement = 0x0330d4bfdc5dab25ed4813570b4975b16a6fd0202bb2373
a00edcb008ac105f51216837973cd29f20744eac13619ce28a2
EvaluationProofC = 0xa79fe0ddd80f3ad91257ad638e6f80328c0779b3e9f90ef
14bb0be6e9131bb268b030562302eb0387ed95fbd6effb086
EvaluationProofS = 0xaf5524e526e0649fce351adcf199251a0f3dc2ec93c8856
5209a64c95ebe5b03ed88f75e1cd1835bf87b3c1c8c3519e6
Info = 0x736f6d655f696e666f
Output = 0x558a6bcecaab839fe9a7020352655cd79ddca1c7c29ac1f062a4a96a6
9b59fd3b385a11481f6fb4c2d8900d1c6897b5d5a6b14c2bd31dc7282d643b963052
9ad

#### Test Vector 3, Batch Size 2

Input = 0x00,0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0xa0d61b2f5a8a2a1143368327f3077c68a1545e9aafbba6a90dc0d4094b
a4283237211e139f306fc904c2d4fe4cc69c0b,0x90320718eff747e2482562df55c
99bf9591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6d688f70cf205f782fa1
2
BlindedElement = 0x0332a05819c8b2c1165d104b43e0b3e2fd49b17dd5e2a3c84
bda805dbcebf20860d3a063d552f1190c6f79e64f01e6aee5,0x0337e5bd41e1b763
aac339f488b158014a31addc5a8c69cdd4fcdc11305dca89fce402fd0ea27f5a6eff
c82dbfb8fc7557
EvaluationElement = 0x03085806170058c5189010e315013a68259e862c08e6ef
21c40b9068dabc4187f611a303c57db80cdc3d9b4e537fcda75c,0x02936ab564ff7
9eeaff16c3fdc176ba71c5351d60ec067daca44b7ebb3c106439ac0aaecaf9f8974a
832690b8e17907150
UnblindedElement = 0x03f76b2ddddcce5db5504f77d07eeccd8302436818c4882
b293499f31255b139aa3ed920002dc2e201b725de580b251852,0x0330d4bfdc5dab
25ed4813570b4975b16a6fd0202bb2373a00edcb008ac105f51216837973cd29f207
44eac13619ce28a2
EvaluationProofC = 0x37de36448a3838fc074c4eb87e1dcda24d80cd8e90ebf77
8f1e6c22a14e87e76691271324e656319cb572c2cf38906a1
EvaluationProofS = 0x89512f46b3282d5cc3cfc816f13ff6213ae66eb97316fcb
b8b1196e50708f3dead470f6913cc7b5bc4655f8a54aacbb4
Info = 0x736f6d655f696e666f
Output = 0x5dba66546a633215df3fb6dc002655f43ed07f497fd1b4ee6f2214fd6
578aebbceabfb3ce03ce005f0f457b6764e74dfa78d72ee5cc21e167a17c67ce8684
7e3,0x558a6bcecaab839fe9a7020352655cd79ddca1c7c29ac1f062a4a96a69b59f
d3b385a11481f6fb4c2d8900d1c6897b5d5a6b14c2bd31dc7282d643b9630529ad

## OPRF(P-521, SHA-512)

### Base Mode

skSm = 0x1b68fade716a6a82d600444b26de335ba38cf092d80c7cf2cb55388d899
515238094c800bdd9c65f71780ba85f5ae9b4703e17e559ca3ccd1944f9a70536c17
5f12

#### Test Vector 1, Batch Size 1

Input = 0x00
Blind = 0xdd0772f68b53baade9962d164565d8c0e3a1ba1a337759061965a423d9
d3d6e1e1006dc8984ad28a4c93ecfc36fc2171046b3c4284855cfa2434ed98db9e68
a598
BlindedElement = 0x0200c90f3a3d634131d2c6c28fb3c68cd4a2fcf645e02bf5d
dada3cd3400fe1a9b11c8149f74e97f305c6bbed99e4bf1d0e4e15648db2f7ca4d37
7fd5e063767d8b878
EvaluationElement = 0x02015d9c192d77d428e77486ba09239c9e9666e3de62d5
787cade4d92e9017993607041fade15f90d8f6b45847b5f5a2c5355d7aa8696aa2a8
a4aef3b1f565c3c8010e
UnblindedElement = 0x03005e3cef397da7e8d193d31107ea2da163eca97b54d6d
6ecd664b9c5021834f355800657bbde325f9c4c5a5a64d5a7651d669b720e46674e0
6914382182dcce16fc7
Info = 0x736f6d655f696e666f
Output = 0x0f742a304c09e4d3548a16417776b8164a2adb5aada68966e4f6f216d
9d1c89465f0ebc01d81a2ed2243637e3f0730e705c752be32b414d4e8b056b5dccc9
280

#### Test Vector 2, Batch Size 1

Input = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0xe8bea293aa8a69353b023f4a0e6a39eef47b0d4ca4c64825ba085de242
042b84d9ebe3b2e9de07678ff96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd
1fa8
BlindedElement = 0x02013e9e1424ad951f402f53dfea37908bba1e03bcb399848
036620779fd2cab5d2d300e78600fcd256cb2d14ccaea3864561d848d561785ddabb
3b01b27155aae312a
EvaluationElement = 0x02014ccf9eeefaca351b8ddebe68b2682c98279a5222fe
740cff6be1cd85c349bdea0e8be5bdb0e25ffa56f222076eaa823a625354809e34b0
8ca8e7e7afd8465cfb14
UnblindedElement = 0x0301938d6f170ce442b762cf25f9d816d22d3ab10f4416a
a06ee061aef19954a1a13b3910d243b3fe046e54cf19d16191d55230b92b4d0a004b
ff74087453425630e1f
Info = 0x736f6d655f696e666f
Output = 0x30d3e2dd8385e2e814a22f36e1edb66034055c99a044745603e32b0f1
f4f743a62a4b98f44b9587521a9387bfd428166db97b433246a7e1a572c29e3729d1
c37

### Verifiable Mode

skSm = 0x1449bb3b4ef3d5c65b55a1b8960563b3420d7764097502850c445ccd86e
2d20d7e4ec77617a4238835743037876080d2e3e27bc3ce7b5fb6a1107ffedeaedb3
7177
pkSm = 0x02010dc16a63cb3e75fb306038b8364f55a1fff4e168538c4667cb15112
60ecae34fe14916ca1d19a0f2e208f537ae634751a9b85d80b33e9c02563de40c86d
1347679

#### Test Vector 1, Batch Size 1

Input = 0x00
Blind = 0x86b18e24c9a40ed5eec262bf51dc970d63acb5ab74318e54223c759e97
47f59c0d4ecbc087302667fabefa647b1766accb7c82a46aa3fc6caecbb9e935f0bf
b00f
BlindedElement = 0x03007023e7afe67d3c5a912bdc703e11822e3d72519a77241
391958603e5356029f8a5ad66a71dd14054ffe6f5b5c5055a151dfcbaf36784c2cec
4ac3802681982afe2
EvaluationElement = 0x0301286ee7068eca78bff9786df0deba99abd288058f41
fad91ba57cb5e946f37da2fb2486c70cc1570230b04b97fa1e732ff898ca032bb0fb
11955b70a226715368d5
UnblindedElement = 0x02006ff10e5a67d2f1b7dd74e5b3d927478b25eecd1cdf0
68139f30dc269f9dc31805b0ef8f2481b922b3b8e90a7a821b3cdb5e0cb4ae4d64ea
c735693038b6cc4503e
EvaluationProofC = 0x1bff02b0ea6c9501a91d3a84f3a91c582f9216974a981ef
bf5c7f7002ad96746a5d72a8430de6f69c22c2d2dc2ba69cc739990eef75b0daf90a
2c5f069569cd3974
EvaluationProofS = 0x1a08833077d1aec89a730429e8062e71bd085a1dbfaa7f6
8953cbf3af5e05dffa7e040db2ee81c1b1f75d8d5d9015ea0fae55f10968c1577aa0
e38e718c4fc8ff80
Info = 0x736f6d655f696e666f
Output = 0x5670e106e2d41747c7b1ac1902818022fe3019062f2cbe57810d21be5
cad0abf32093be1b3db99dc49ce5d2b39c4667a88a397dedff2068286c49f2c11f2b
5ed

#### Test Vector 2, Batch Size 1

Input = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0xb9f3ad744eb5baf418275e45ab31ade30669dbae98fb0879524fb9234e
93a8bd048ad9f44b428026396a810328c405a354e666f086fa0ea4754fb56527be01
0297
BlindedElement = 0x0200df8a5b7753f5a6a640e6db207649cb07e3a76931a40e9
c40e54dce933c26f0450461b2885eab5a202485ba35ae2ff006964b88af4069b68b9
c1554c3e940e0b943
EvaluationElement = 0x0200736c0d07ce6ccda8f0a8e31218ed844f7729c99438
811f0d91a3cab6b0cde7b726cd65f9622e757d06bd8dad2894601e1635b3d345193a
7ce47e2d58b5bfb5ffa3
UnblindedElement = 0x02001f091d698d71ab48a00104ef005dd1feb85ca48bc5d
113c9e6c2df3f079b8888d1ef24e0bfee75d90c712bc5d7ecd655b32cb7f0259654b
acbf9766801ecc9a29f
EvaluationProofC = 0x19090a83fd579e254811a733469eaf9163efa8397bf61d5
4bc9f0b3d919e2e92ffddcdf8639bbad1cd9696d9f568452eef1ced4a3861af505dc
daf6321c7b3a069d
EvaluationProofS = 0x532d796210ea9e5eea285d358c8fdb4a1e8bc7559389276
5e13db6f64a52830fa2c55a1e5039f4aeea2309bdb1bb55f964113d4b25fd169cb91
fd93dce6afd6199
Info = 0x736f6d655f696e666f
Output = 0xd9ee7a801a46c8c5c69c11340073b56f6ed4bec7a2b31b6e6776246be
b9717f37c966f3e98f2156a3905f8c4ddc3740afaa653333718c37e46b5d06e4570d
7b0

#### Test Vector 3, Batch Size 2

Input = 0x00,0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0x1daf5685928c72d9dab8ddfe45de734ce0d4ff5823d2e40c4fcf880e9a
8272b46eea593b1095e7d38ba6ff37c42b3c4859761247a74d0c62c98ddff1365bb9
b82b3,0xb96540574e2bc92534ac475d6a3649f3e9cdf20a7e882066be571714f5db
073555bc1bfebe1d50a04fd6656a439cf465109653bf8e484c01c5f8516f98f3159b
40
BlindedElement = 0x0300d45e787f24a39c52cc290f0b202c03d320b1213a9dd44
29df6b7f455a954b85815b5b379db5b4b9d665abaaf26366c91b8cd4884a2cddbf5b
e07420726de773fb7,0x030122ca1ad84feb6dc2832373011608a6d7f7f8e632c66c
c6e134de50aa4317caa9c9b11cb281ae7dea4286a7c217cb9937d470f28a8c800dce
277a759342dd9a3e0d
EvaluationElement = 0x0301d8af9135b69b174238acd802e31323e84f9f66c7d3
ca68659ccd4456f16af156c15d48c8d7003f64fc8d814d09e5e4f0bf54dfd719ddaf
1019f667ea0f9e58afed,0x0300e253175c05483e6696eb6447f4e3ae87c07649097
49a64c902dbe11a8d575e59d13c86f499483f99d707d5485ca441e48cc9e0f78fbb2
2225b91c8870f8d094aae
UnblindedElement = 0x02006ff10e5a67d2f1b7dd74e5b3d927478b25eecd1cdf0
68139f30dc269f9dc31805b0ef8f2481b922b3b8e90a7a821b3cdb5e0cb4ae4d64ea
c735693038b6cc4503e,0x02001f091d698d71ab48a00104ef005dd1feb85ca48bc5
d113c9e6c2df3f079b8888d1ef24e0bfee75d90c712bc5d7ecd655b32cb7f0259654
bacbf9766801ecc9a29f
EvaluationProofC = 0xef808190325fb49195e5244c1477694ef2770626369dd0a
d0a428a0482ae69b837ff8e9d34e347ee8bf5e6a30d6ef7b9c8e995ef3aca5a45218
c5ff97cf4bade00
EvaluationProofS = 0x1b7c17f5474a7fdd637e6351566b7606e1b03ac034728e2
45a855278bc245fe2d1fb6c93180b4904f1037909d2ea8746ac806e507b7de668cc1
30de7264da4003e2
Info = 0x736f6d655f696e666f
Output = 0x5670e106e2d41747c7b1ac1902818022fe3019062f2cbe57810d21be5
cad0abf32093be1b3db99dc49ce5d2b39c4667a88a397dedff2068286c49f2c11f2b
5ed,0xd9ee7a801a46c8c5c69c11340073b56f6ed4bec7a2b31b6e6776246beb9717
f37c966f3e98f2156a3905f8c4ddc3740afaa653333718c37e46b5d06e4570d7b0
