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
  ChaumPedersen:
    title: "Wallet Databases with Observers"
    target: https://chaum.com/publications/Wallet_Databases.pdf
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
A Verifiable OPRF (VOPRF) is an OPRF wherein the server can prove to
the client that F(k, x) was computed using the key k. A Partially-Oblivious
PRF (POPRF) is a variant of a VOPRF wherein client and server interact
in computing F(k, x, y), for some PRF F with server-provided key k,
client-provided input x, and public input y, and client receives proof
that F(k, x, y) was computed using k. A POPRF with fixed input y is
functionally equivalent to a VOPRF.

OPRFs have a variety of applications, including: password-protected secret
sharing schemes {{JKKX16}}, privacy-preserving password stores {{SJKS17}}, and
password-authenticated key exchange or PAKE {{!I-D.irtf-cfrg-opaque}}.
Verifiable POPRFs are necessary in some applications such as Privacy Pass
{{!I-D.davidson-pp-protocol}}. Verifiable POPRFs have also been used for
password-protected secret sharing schemes such as that of {{JKK14}}.

This document specifies OPRF, VOPRF, and POPRF protocols built upon
prime-order groups based on the 2HashDH {{JKKX16}} and 3HashSDHI {{TCRSTW21}}
designs, respectively. The document describes each protocol variant,
along with application considerations, and their security properties.

## Change log

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
- I2OSP and OS2IP: Convert a byte array to and from a non-negative
  integer as described in {{!RFC8017}}. Note that these functions
  operate on byte arrays in big-endian byte order.
- For any two byte strings `a` and `b`, `CT_EQUAL(a, b)` represents
  constant-time equality between `a` and `b` which returns `true` if
  `a` and `b` are equal and `false` otherwise.

For serialization, all data structure descriptions use TLS notation {{RFC8446, Section 3}}.

All algorithms and procedures described in this document are laid out
in a Python-like pseudocode.

String values such as "Context-" are ASCII string literals.

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

Two functions can be used for generating a key pair (`skS`, `pkS`)
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

## Discrete Log Equivalence Proofs {#dleq}

Another important piece of the OPRF protocols in this document is proving
that the discrete log of two values is identical in zero knowledge, i.e.,
without revealing the discrete logarithm. This is referred to as a discrete
log equivalence (DLEQ) proof. This section describes functions
for non-interactively proving and verifying this type of statement,
built on a Chaum-Pedersen {{ChaumPedersen}} proof. It is split into
two sub-sections: one for generating the proof, which is done by servers
in the verifiable protocols, and another for verifying the proof, which is
done by clients in the protocol.

### Proof Generation

Generating a proof is done with the `GenerateProof` function, defined below.
This function takes four Elements, A, B, C, and D, and a single
group Scalar k, and produces a proof that `k*A == B` and `k*C == D`.
The output is a pair of serialized Scalars concatenated together,
denoted as type `Proof`.

~~~
GenerateProof

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
  (M, Z) = ComputeCompositesFast(k, B, Cs, Ds)

  r = GG.RandomScalar()
  t2 = r * A
  t3 = r * M

  Bm = GG.SerializeElement(B)
  a0 = GG.SerializeElement(M)
  a1 = GG.SerializeElement(Z)
  a2 = GG.SerializeElement(t2)
  a3 = GG.SerializeElement(t3)

  challengeDST = "Challenge"
  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  c = GG.HashToScalar(h2Input)
  s = (r - c * k) mod p

  proof = GG.SerializeScalar(c) || GG.SerializeScalar(s)
  return proof
~~~

The helper function ComputeCompositesFast is as defined below.

~~~
ComputeCompositesFast

Input:

  Scalar k
  Element B
  Element Cs[m]
  Element Ds[m]

Output:

  Element M
  Element Z

def ComputeCompositesFast(k, B, Cs, Ds):
  Bm = GG.SerializeElement(B)
  seedDST = "Seed-" || contextString
  h1Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(seedDST), 2) || seedDST
  seed = Hash(h1Input)

  M = GG.Identity()
  for i = 0 to m-1:
    Ci = GG.SerializeElement(Cs[i])
    Di = GG.SerializeElement(Ds[i])
    compositeDST = "Composite"
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(Ci), 2) || Ci ||
              I2OSP(len(Di), 2) || Di ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    M = di * Cs[i] + M

  Z = k * M

 return (M, Z)
~~~

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
VerifyProof

Input:

  Element A
  Element B
  Element C
  Element D
  Proof proof

Output:

  boolean verified

Errors: DeserializeError

def VerifyProof(A, B, C, D, proof):
  Cs = [C]
  Ds = [D]

  (M, Z) = ComputeComposites(B, Cs, Ds)
  c = GG.DeserializeScalar(proof.c)
  s = GG.DeserializeScalar(proof.s)

  t2 = ((s * A) + (c * B))
  t3 = ((s * M) + (c * Z))

  Bm = GG.SerializeElement(B)
  a0 = GG.SerializeElement(M)
  a1 = GG.SerializeElement(Z)
  a2 = GG.SerializeElement(t2)
  a3 = GG.SerializeElement(t3)

  challengeDST = "Challenge"
  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            I2OSP(len(challengeDST), 2) || challengeDST

  expectedC = GG.HashToScalar(h2Input)

  return expectedC == c
~~~

The definition of `ComputeComposites` is given below.

~~~
ComputeComposites

Input:

  Element B
  Element Cs[m]
  Element Ds[m]

Output:

  Element M
  Element Z

def ComputeComposites(B, Cs, Ds):
  Bm = GG.SerializeElement(B)
  seedDST = "Seed-" || contextString
  h1Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(seedDST), 2) || seedDST
  seed = Hash(h1Input)

  M = GG.Identity()
  Z = GG.Identity()
  for i = 0 to m-1:
    Ci = GG.SerializeElement(Cs[i])
    Di = GG.SerializeElement(Ds[i])
    compositeDST = "Composite"
    h2Input = I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
              I2OSP(len(Ci), 2) || Ci ||
              I2OSP(len(Di), 2) || Di ||
              I2OSP(len(compositeDST), 2) || compositeDST
    di = GG.HashToScalar(h2Input)
    M = di * Cs[i] + M
    Z = di * Ds[i] + Z

 return (M, Z)
~~~

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
    Client                                              Server(skS)
  ---------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

                      evaluatedElement = Evaluate(blindedElement)

                             evaluatedElement
                               <----------

  output = Finalize(input, blind, evaluatedElement, blindedElement)
~~~
{: #fig-oprf title="OPRF protocol overview"}

In the verifiable mode, the client additionally receives proof that the server used `skS` in
computing the function. To achieve verifiability, as in the original work of {{JKK14}}, the
server provides a zero-knowledge proof that the key provided as input by the server in
the `Evaluate` function is the same key as it used to produce the server's public key.
This proof does not reveal the server's private key to the client. This interaction
is shown below.

~~~
    Client(pkS)                                     Server(skS, pkS)
  ---------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

               evaluatedElement, proof = Evaluate(blindedElement)

                         evaluatedElement, proof
                               <----------

  output = Finalize(input, blind, evaluatedElement, blindedElement, proof)
~~~
{: #fig-voprf title="VOPRF protocol overview with additional proof"}

The partially-oblivious mode extends the VOPRF mode such that the client and server can additionally provide a public
input `info` that is used in computing the pseudorandom function. That is, the client and server
interact to compute `output = F(skS, input, info)`. To support additional public input,
the client and server augment the `pkS` and `skS`, respectively, using the `info` value,
as in {{TCRSTW21}}.

~~~
    Client(pkS, info)                          Server(skS, pkS, info)
  ---------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

               evaluatedElement, proof = Evaluate(blindedElement, info)

                         evaluatedElement, proof
                               <----------

  output = Finalize(input, blind, evaluatedElement, blindedElement, proof, info)
~~~
{: #fig-poprf title="POPRF protocol overview with additional public input"}

Each protocol consists of an offline setup phase and an online phase,
described in {{offline}} and {{online}}, respectively. Configuration details
for the offline phase are described in {{configuration}}.

## Configuration

Each of the three protocol variants are identified with a one-byte value:

| Mode           | Value |
|:===============|:======|
| modeOPRF       | 0x00  |
| modeVOPRF      | 0x01  |
| modePOPRF      | 0x02  |

Additionally, each protocol variant is instantiated with a ciphersuite,
or suite. Each ciphersuite is identified with a two-byte value, referred
to as `suiteID`; see {{ciphersuites}} for the registry of initial values.

## Offline Context Setup {#offline}

In the offline setup phase, both the client and server create a context used
for executing the online phase of the protocol. The key pair (`skS`, `pkS`)
should be generated by calling either `GenerateKeyPair` or `DeriveKeyPair`.
Additionally, they agree on a ciphersuite value `suiteID`. These values are
combined to create a "context string" using the following function:

~~~
def CreateContextString(mode, suiteID):
  return "VOPRF08-" || I2OSP(mode, 1) || I2OSP(suiteID, 2)
~~~

[[RFC editor: please change "VOPRF08" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

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
for each protocol variant. Throughout each description the following implicit
parameters are assumed to exist:

- GG, a prime-order group implementing the API described in {{pog}}.
- contextString, a domain separation tag constructed during context setup as created in {{offline}}.
- skS and pkS, the private and public keys configured for client and server in {{offline}}.

Moreover, the data types `PrivateInput` and `PublicInput` are opaque byte
strings of arbitrary length no larger than 2^13 octets.

### OPRF Protocol {#oprf}

The OPRF protocol begins with the client blinding its input, as described
by the `Blind` function below.

~~~
Blind

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

Clients store `blind` locally, and send `blindedElement` to the server for evaluation.
Upon receipt, servers evaluate `blindedElement` using the `Evaluate` function
described below.

~~~
Evaluate

Input:

  SerializedElement blindedElement

Output:

  SerializedElement evaluatedElement

Errors: DeserializeError

def Evaluate(blindedElement):
  R = GG.DeserializeElement(blindedElement)
  Z = skS * R
  evaluatedElement = GG.SerializeElement(Z)

  return evaluatedElement
~~~

Servers send the output `evaluatedElement` to clients for processing. Recall that
servers may batch multiple client inputs to `Evaluate`.

Upon receipt of `evaluatedElement`, clients complete the OPRF evaluation
using the `Finalize` function described below.

~~~
Finalize

Input:

  PrivateInput input
  Scalar blind
  SerializedElement evaluatedElement

Output:

  opaque output[Nh]

Errors: DeserializeError

def Finalize(input, blind, evaluatedElement):
  Z = GG.DeserializeElement(evaluatedElement)
  N = blind^(-1) * Z
  unblindedElement = GG.SerializeElement(N)

  finalizeDST = "Finalize"
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              I2OSP(len(finalizeDST), 2) || finalizeDST
  return Hash(hashInput)
~~~

### VOPRF Protocol {#voprf}

The VOPRF protocol begins with the client blinding its input, using the same
`Blind` function as in {{oprf}}. Clients store the output `blind` locally
and send `blindedElement` to the server for evaluation. Upon receipt,
servers compute an evaluated element and DLEQ proof using the following
`Evaluate` function.

~~~
Evaluate

Input:

  SerializedElement blindedElement

Output:

  SerializedElement evaluatedElement
  Proof proof

Errors: DeserializeError

def Evaluate(blindedElement):
  R = GG.DeserializeElement(blindedElement)
  Z = skS * R
  proof = GenerateProof(skS, G, pkS, R, Z)
  evaluatedElement = GG.SerializeElement(Z)
  return evaluatedElement, proof
~~~

The server sends both `evaluatedElement` and `proof` back to the client.
Upon receipt, the client completes the VOPRF computation using the
`Finalize` function below.

~~~
Finalize

Input:

  PrivateInput input
  Scalar blind
  SerializedElement evaluatedElement
  SerializedElement blindedElement
  Proof proof

Output:

  opaque output[Nh]

Errors: DeserializeError, VerifyError

def Finalize(input, blind, evaluatedElement, blindedElement, proof):
  R = GG.DeserializeElement(blindedElement)
  Z = GG.DeserializeElement(evaluatedElement)
  if VerifyProof(G, pkS, R, Z, proof) == false:
    raise VerifyError

  N = blind^(-1) * Z
  unblindedElement = GG.SerializeElement(N)

  finalizeDST = "Finalize"
  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              I2OSP(len(finalizeDST), 2) || finalizeDST
  return Hash(hashInput)
~~~

### POPRF Protocol {#poprf}

The POPRF protocol begins with the client blinding its input, using the same
`Blind` function as in {{oprf}}. Clients store the output `blind` locally
and send `blindedElement` to the server for evaluation. Upon receipt,
servers compute an evaluated element and DLEQ proof using the following
`Evaluate` function.

~~~
Evaluate

Input:

  SerializedElement blindedElement
  PublicInput info

Output:

  SerializedElement evaluatedElement
  Proof proof

Errors: DeserializeError, InverseError

def Evaluate(blindedElement, info):
  R = GG.DeserializeElement(blindedElement)
  context = "Info" || I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)
  t = skS + m
  if t == 0:
      raise InverseError
  Z = t^(-1) * R

  U = ScalarBaseMult(t)
  proof = GenerateProof(t, G, U, Z, R)
  evaluatedElement = GG.SerializeElement(Z)
  return evaluatedElement, proof
~~~

The server sends both `evaluatedElement` and `proof` back to the client.
Upon receipt, the client completes the VOPRF computation using the
`Finalize` function below.

~~~
Finalize

Input:

  PrivateInput input
  Scalar blind
  SerializedElement evaluatedElement
  SerializedElement blindedElement
  Proof proof
  PublicInput info

Output:

  opaque output[Nh]

Errors: DeserializeError, VerifyError

def Finalize(input, blind, evaluatedElement, blindedElement, proof, info):
  context = "Info" || I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)

  R = GG.DeserializeElement(blindedElement)
  Z = GG.DeserializeElement(evaluatedElement)

  T = ScalarBaseMult(m)
  U = T + pkS
  if VerifyProof(G, U, Z, R, proof) == false:
    raise VerifyError

  N = blind^(-1) * Z
  unblindedElement = GG.SerializeElement(N)

  finalizeDST = "Finalize"
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
treatment and public input representation for the POPRF protocol variant.

## Error Considerations

Some OPRF variants specified in this document have fallible operations. For example, `Finalize`
and `Evaluate` can fail if any element received from the peer fails deserialization.
The explicit errors generated throughout this specification, along with the
conditions that lead to each error, are as follows:

- `VerifyError`: Verifiable OPRF proof verification failed; {{voprf}} and {{poprf}}.
- `DeserializeError`: Group element or scalar deserialization failure; {{pog}}.
- `InverseError`: A scalar is zero and has no inverse; {{pog}}.

The errors in this document are meant as a guide to implementors. They are not
an exhaustive list of all the errors an implementation might emit. For example,
implementations might run out of memory and return a corresponding error.

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

Implementations may choose to not let applications control `info` in cases where
this value is fixed or otherwise not useful to the application. In this case,
the resulting protocol is functionally equivalent to an OPRF without public
input. See {{equiv-2hashdh}} for discussion about repurposing existing non-verifiable
OPRF implementations, i.e., those without the `info` parameter, using the construction
in this specification.

# Security Considerations {#sec}

This section discusses the cryptographic security of our protocol, along
with some suggestions and trade-offs that arise from the implementation
of a POPRF.

## Security Properties {#properties}

The security properties of a POPRF protocol with functionality
y = F(k, x, t) include those of a standard PRF. Specifically:

- Pseudorandomness: F is pseudorandom if the output y = F(k, x, t) on any
  input x is indistinguishable from uniformly sampling any element in
  F's range, for a random sampling of k.

In other words, consider an adversary that picks inputs x from the
domain of F and evaluates F on (k, x, t) (without knowledge of randomly
sampled k). Then the output distribution F(k, x, t) is indistinguishable
from the output distribution of a randomly chosen function with the same
domain and range.

A consequence of showing that a function is pseudorandom, is that it is
necessarily non-malleable (i.e. we cannot compute a new evaluation of F
from an existing evaluation). A genuinely random function will be
non-malleable with high probability, and so a pseudorandom function must
be non-malleable to maintain indistinguishability.

A POPRF protocol must also satisfy the following property:

- Partial obliviousness: The server must learn nothing about the client's
  private input or the output of the function. In addition, the client must
  learn nothing about the server's private key. Both client and server learn
  the public input (info).

Essentially, partial obliviousness tells us that, even if the server learns
the client's private input x at some point in the future, then the server will
not be able to link any particular POPRF evaluation to x. This property is
also known as unlinkability {{DGSTV18}}.

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

## Cryptographic Security {#cryptanalysis}

Below, we discuss the cryptographic security of each protocol variant
from {{protocol}}, relative to the necessary cryptographic assumptions
that need to be made.

### OPRF and VOPRF Assumptions

The OPRF and VOPRF protocol variants in this document are based on {{JKK14}}.
In fact, the VOPRF construction is identical to the {{JKK14}} construction, except
that this document supports batching so that multiple evaluations can happen
at once whilst only constructing one proof object. This is enabled using
an established batching technique.

Consequently, the cryptographic security of the OPRF and VOPRF variants is based on
the assumption that the One-More Gap DH is computationally difficult to solve.

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

The original paper {{JKK14}} gives a security proof that the 2HashDH-NIZK
construction satisfies the security guarantees of a VOPRF protocol {{properties}}
under the OMDH assumption in the universal composability (UC) security model.

### Q-Strong-DH Oracle {#qsdh}

A side-effect of the OPRF and VOPRF protocols is that it allows instantiation of
a oracle for constructing Q-strong-DH (Q-sDH) samples. The Q-Strong-DH
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
reduce the security of the instantiation by log\_2(2^20)/2 = 10 bits.
Launching this attack would require 2^(p/2-log\_2(Q)/2) bits of memory.

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

### POPRF Assumptions

The POPRF construction in this document is based on the construction known
as 3HashSDHI given by {{TCRSTW21}}. The construction is identical to
3HashSDHI, except that this design can optionally perform multiple POPRF
evaluations in one go, whilst only constructing one NIZK proof object.
This is enabled using an established batching technique.

The cryptographic security of the construction is based on the assumption
that the One-More Gap Strong Diffie-Hellman Inversion (SDHI) assumption from
{{TCRSTW21}} is computationally difficult to solve. {{TCRSTW21}} show that
both the One-More Gap Computational Diffie Hellman (CDH)
assumption and the One-More Gap SDHI assumption reduce to the q-DL assumption
in the algebraic group model, for some q number of `Evaluate` queries.
(The One-More Gap CDH assumption was the hardness assumption used to
evaluate the 2HashDH-NIZK construction from {{JKK14}}, which is a predecessor
to the design in this specification.)

#### Static q-DL Assumption

As with the OPRF and VOPRF variants, a side-effect of the POPRF design is
that it allows instantiation of an oracle for retrieving "strong-DH"
evaluations, in which an adversary can query a group element
B and scalar c, and receive evaluation output 1/(k+c)\*B. This type of oracle allows
an adversary to form elements of "repeated powers" of the server-side secret. This
"repeated powers" structure has been studied in terms of the q-DL problem which
asks the following: Given G1, G2, h\*G2, (h^2)\*G2, ..., (h^Q)\*G2; for G1 and G2
generators of GG. Output h where h is an element of GF(p)

For example, consider an adversary that queries the strong-DH oracle provided by the
POPRF on a fixed scalar c starting with group element G2, then passes the received
evaluation group element back as input for the next evaluation. If we set h = 1/(k+c),
such an adversary would receive exactly the evaluations given in the q-DL problem: h\*G2,
(h^2)\*G2, ..., (h^Q)\*G2.

{{TCRSTW21}} capture the power of the strong-DH oracle in the One-More Gap SDHI assumption
and show, in the algebraic group model, the security of this assumption can be reduced to
the security of the q-DL problem, where q is the number of queries made to the blind
evaluation oracle.

The q-DL assumption has been well studied in the literature, and there exist a number of
cryptanalytic studies to inform parameter choice and group instantiation (for example,
{{BG04}} and {{Cheon06}}).

### 2HashDH OPRF Equivalence {#equiv-2hashdh}

The non-verifiable 3HashSDHI POPRF construction in this specification is equivalent
to the non-verifiable 2HashDH OPRF from {{JKK14}} when the input `info` is fixed.
In particular, the 3HashSDHI POPRF computes the following given private key `k`,
private input `x`, and public input `t`, where H1, H2, and H3 are GG.HashToGroup,
GG.HashToScalar, and Hash, respectively:

~~~
H3(x, H1(x)^(1 / (k + H2(t))))
~~~

Similarly, the 2HashDH OPRF computes the following given private key `k'` and
private input `x`:

~~~
H3(x, H1(x)^k')
~~~

Given a fixed public input `t`, one can transform a 3HashSDHI private key `k`
into an equivalent 2HashDH private key `k'` as follows:

~~~
k' = 1 / (k + H2(t))
~~~

This transformation is undefined for values of `k` and `t` such that
`k + H2(t) = 0`. Because only a single choice of `k` leads to this
undefined case, the distribution of `k'` defined via this transformation
is statistically close to the distribution of a randomly sampled `k'`
as output from `GG.GenerateKeyPair`.

Note that one can also transform any non-zero 2HashDH private key `k'` into
an equivalent 3HashSDHI private key `k` as follows:

~~~
k = (1 - (k' * H2(t))) / k'
~~~

### Implications for Ciphersuite Choices

The POPRF instantiations that we recommend in this document are informed
by the cryptanalytic discussion above. In particular, choosing elliptic
curves configurations that describe 128-bit group instantiations would
appear to in fact instantiate a POPRF with 128-(log\_2(Q)/2) bits of
security. Moreover, such attacks are only possible for those certain
applications where the adversary can query the POPRF directly.
In applications where such an oracle is not made available this security loss does not apply.

In most cases, it would require an informed and persistent attacker to
launch a highly expensive attack to reduce security to anything much
below 100 bits of security. We see this possibility as something that
may result in problems in the future. Applications that admit the
aforementioned oracle functionality, and that cannot tolerate discrete
logarithm security of lower than 128 bits, are RECOMMENDED to only
implement ciphersuites 0x0002, 0x0004, and 0x0005.

## Proof Randomness

It is essential that a different `r` value is used for every invocation
of GenerateProof. Failure to do so may leak `skS` as is possible in Schnorr
or (EC)DSA scenarios where fresh randomness is not used.

## Domain Separation {#domain-separation}

Applications SHOULD construct input to the protocol to provide domain
separation. Any system which has multiple POPRF applications should
distinguish client inputs to ensure the POPRF results are separate.
Guidance for constructing info can be found in {{!I-D.irtf-cfrg-hash-to-curve, Section 3.1}}.

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

## Timing Leaks

To ensure no information is leaked during protocol execution, all
operations that use secret data MUST run in constant time. Operations that
SHOULD run in constant time include all prime-order group operations and
proof-specific operations (`GenerateProof()` and `VerifyProof()`).

# Acknowledgements

This document resulted from the work of the Privacy Pass team
{{PrivacyPass}}. The authors would also like to acknowledge helpful
conversations with Hugo Krawczyk. Eli-Shaoul Khedouri provided
additional review and comments on key consistency. Daniel Bourdrez,
Tatiana Bradley, Sofia Celi, Frank Denis, Kevin Lewi, and Bas Westerbaan
also provided helpful input and contributions to the document.

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

### OPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 74db8e13d2c5148a1181d57cc06debd730da4df1978b72ac18bc48992a0d2
c0f
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = 744441a5d3ee12571a84d34812443eba2b6521a47265ad655f0
1e759b3dd7d35
EvaluationElement = 5238fc69e584025f803c1126f3493c9bad2777b60b1946dd
bf05922fe2a77533
Output = 18b8518de0d2d0af4f6665fc7d569c1ebdbb1ebfeda66da5ab7f16f3c6b
36aa8aeba42db687f57d9ece896db108b2104cbd339917ec47f4072a342c303943e8
9
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = f4eeea4e1bcb2ec818ee2d5c1fcec56c24064a9ff4bea5b3dd6
877800fc28e4d
EvaluationElement = 90f841bace4f20ba5b30c30e415b0f06158f793ab008848b
6262d0d27415c266
Output = 2015858d38cad886a5844eedb897f0519344ee85e5a98404e82b0a7c963
d6b00b315fd6ab93672e778b4334a51806ef51265c0f26c0d7aff32cbc0c77ced3c5
d
~~~

### VOPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = ad08ad9c7107691d792d346d743e8a79b8f6ae0673d58cbf7389d7003598c
903
pkSm = 7a5627aec2f2209a2fc62f39f57a8f5ffc4bbfd679d0273e6081b2b621ee3
b52
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 56c6926e940df23d5dfe6a48949c5a9e5b503df3bff36454ba4
821afa1528718
EvaluationElement = a6c7f6b6ecd9d040dd9490d6b3f42cf4ac51ae009c737015
f03d5293d0d9444e
Proof = b3cbde12be9635f67fd1053d83c7dae31f6d34d0226426ecd883b4b4c84f
c40788fcf7ee8a37f95f2a1a3d447c1f5e5f60a4052d0229220317053b14b2edaf07
ProofRandomScalar = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9d
bcec831b8c681a09
Output = 916cc21f9cc63d7103f679613bea5cc570716ed447b3248becce8a6aae5
be04ba8dab29f7e9e898930d0e3c3c79ac76afec07b57d8e3aac9478abe7531f0422
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = 5cd133d03df2e1ff919ed85501319c2039853dd7dc59da73605
fd5791b835d23
EvaluationElement = 38f1c43a0ff7de2de2fe5118e46258854426d90d8cc18f4e
7c5407ec4155b124
Proof = 725e728db659ac68a2272a37d039d0525748933fcf6e82695442d930e7b4
120b50fce0899e65db9764d9b67b492344a3b49b4758cc25944ddf4d6ca0ea818d0a
ProofRandomScalar = 74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df
9d013f7d6c312a0b
Output = f0bb75b090c745aefb8c36eb9d5fd61133454d101772c3a9a6007ea3543
df97f778c86d9951668301a881424dcda8f9f45dde79dfefff42db9e8aa78f394787
8
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0
d50f,533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0
c
BlindedElement = 1c7ee9c1b4145dabeba9ad159531432a20718cb44a86f79dc73
f6f8671c9bf5e,7c1ef37881602cb6d3cf995e6ee310ed51e39b80ce0a825a316bc6
21d0580a14
EvaluationElement = 14551ccb502a3a54a8939f7202209527fbea63003de298c2
252adeb39d79a529,96660c2a6cf50b47c368f99652869016d148b99ca20ed0b0e1d
5bad6fdc82002
Proof = 70df9a3eb24a8f82e084550c24e4e8c1b7065b940fb6bf11fb311069894f
77011462476834a7e37a54b2c1640fb9c8e5b38ad8d122cea4991bb50943badfa203
ProofRandomScalar = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186
a9706137886dce08
Output = 916cc21f9cc63d7103f679613bea5cc570716ed447b3248becce8a6aae5
be04ba8dab29f7e9e898930d0e3c3c79ac76afec07b57d8e3aac9478abe7531f0422
7,f0bb75b090c745aefb8c36eb9d5fd61133454d101772c3a9a6007ea3543df97f77
8c86d9951668301a881424dcda8f9f45dde79dfefff42db9e8aa78f3947878
~~~

### POPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 7e759858c6eb14698e57df64fb14115b450ada6bd4c686af96f9522d76c86
306
pkSm = ba05e4328cac4174274fc70ac4118a889b108cf1efc8ba5bc79abfdcb61ba
846
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc1e9213a043b743b9
5800
BlindedElement = a045ba27352937407c6c3f09ae1ad7b8ccd4ee120df5e92dcd2
2014756e17806
EvaluationElement = de0093534bc20908ce8ab02bdafec7d76b3f84069316a156
13f1d2c8c5ac9954
Proof = 1151421aaff3e846f4e34e0f5984491ec09561e0c83010eb687d6a97eb56
be093529b64076a82e8df946cd7dd190136cf5b30e2dc15c77e079f67bbdc488da01
ProofRandomScalar = 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6ca5b9
14b335512fe70508
Output = dcbfad08aade53c05aa08845536dd4264059fff567f0026dd455e5f1e6a
c4516be2c0f91850c031e8a867151ec1821a04b78ca29873f0f9b22239865e626c96
b
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = de2e98f422bf7b99be19f7da7cac62f1599d35a225ec6340149a0aaff310
2003
BlindedElement = aad45f3d7d66884129d3048614dcd3e35bb0fbac66f073b916b
8ab66c7252249
EvaluationElement = eefada2c7496d4857f61a1cea32768c98a6a6ee8d7536d28
69e593bc5e04d55d
Proof = c2a4910d95e278023966766ea83224c1f2ebefa03d3ac5e77677615bafa3
59068445a64203daba28ec2a0ca8d00bca0a3a2eeb718a9174633b12b728e1a71e09
ProofRandomScalar = c4d002aa4cfcf281657cf36fe562bc60d9133e0e72a74432
f685b2b6a4b42a0c
Output = a2367193d705a1f0d62ac1d0510115b735dd779a3d379bd218ca547fadd
d8dfa396bcd7d3fe4d8024dd1ba25fd1a69e477304497261bb61f7baebfd2b4eeef1
3
~~~

## OPRF(decaf448, SHAKE-256)

### OPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 82c2a6492e1792e6ccdf1d7cff410c717681bd53ad47da7646b14ebd05885
53e4c034e02b3ae5e724600a17a638ad528c04f793df56c2618
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = d3a425c41eac0e313a47e99d05df72c6e1d58e654a5ee9354b115060bca8
7db7d73e00cbb8559f84cb7a221b235b0950a0ab553f40bcc304
BlindedElement = ae09cc0ef98064e4d0b3a295026d62ce80b4be8e44aae716fe3
5c1536fecd0aff874fe7553bbd3c609558a8c5474a8762ebf8056839dcc0f
EvaluationElement = fa50b47b6f9c16b130ae267de20ed65e56484ab89aa01cb8
d89f63ab6ec91a7686a516a3c83591a22627328f242390c21f670a69497c079d
Output = e28913a4789b3e296ee0b86db7476d6327012aebe7a98e5052096dd7021
400ac449d2a7378e0590b5d804c134d4be232e6215fbbab5daf470ea0f3eed414440
0
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 87abe954011b7da62bb6599418ef90b5d4ea98cca1bcd65fa514f1894bcf
6a1c7cef33909b794fe6e69a642b20f4c9118febffaf9a5acc11
BlindedElement = 863a8628a9837efbc0d1caeb69fd5b31c6fd3359d8e74fc07c3
911dbaa6103dfb7b7b6c0b86f50db7b151fc61d1079c271abd402a2932d20
EvaluationElement = 4e8ce7c6cbffd0d3117c733051b0e087667b7d147cf7242d
4343cca984808fcb0e9dcf7e98322789e01a3249087c30fc7062d5c83890a568
Output = 0fbb4daf34f333e0981e6811dad3289b33e5a6ef62cbad7549e331b9512
02070448f7f18193451240365a9b3dfbc2296b0c1d5ad15fbc65cc39812b79889304
7
~~~

### VOPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 5d295b55d1d6e46411bbb4151d154dc61711012ff2390255b3345988f8e3c
458089d52e9b1d837049898f9e4e63a4534f0ed3b3a47c7051c
pkSm = 8e623ef9b65ef2ce148ce56249ee5e69ed6acd3e504a07905cc4c09312551
8d30ae7d6de274438b822d5a55a4365216ac588a4c400fbf6ff
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 20e7794aa77ced123f07e56cc27de60b0ab106c0e1aac79e92dd2d051e90
efe4e2e093bc1e82b80e8cce6afa798ac214abffabac4a096005
BlindedElement = 5cc67ce84bd60ef4760cbd864aefd7d30767a7d6ba6c7af63bc
11347ccab9b59f9bf09cb76e627f061f46501a1f05a8d7cf11a24dc0d9c1b
EvaluationElement = 16f46e03d10285656d3acc05f0f4ef838e4031694ecad71c
fa166793dce520054edc67ba6a9b8428220eaf45a3411581db2ac5707d3b500e
Proof = 62d3167525f8ed89f3237260bf45a1129de76c6eeab1e01bddc6c356b385
13c96922174c07d291e83b7cf579185cd32f496f319f82ca251a68dff30fd42738b6
241aa823771d2fe796626d149c7d952c6a4e010a2ed8cdf15d3c3ab8965786d35529
db4f15ad73c2baef128d173d0d0a
ProofRandomScalar = da3e9faf0f2009d16c797646097d761e2b84e0df5d76ece5
658b3aab5207735beb86c5379228da260159dc24f7c5c2483a81aff8f6ff991b
Output = 1ee014a35d6f9668f1c66b6003b04cf14d11f47019401954d40b80e4d67
82f47da616410953283932ea7baf281f7c8ce4fdc391ba5d7f1473612f0d3325a858
9
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = befcb571168f337dd52851d4bc07947c858dc735e9e22aaf0576f161ab55
5182908dbd7947b1c988956fa73b17b373b72fd4e3c08992892a
BlindedElement = 8cbf06254ec3393734d50a9cbf7b6b27bc18706a49f4c559ee7
aa4642b1295d5de7e9f1150d51611660344d8a194c584fbbc1e1908428a72
EvaluationElement = de4cd9d4250c18bae746e46729aa192f85722b9cb2355523
f6d7241667e7531ab3d9a03af90c4cde1ea699619eed124c55bfa688b231dc90
Proof = a5e775a322f634a7fc8c728a4f40c1cff765de22e1458b6bd749f5256c75
8cda6c8dd640c48675f210b292c70edad044cb18a6b4699b09352c6258fd6bc9a5f3
57b15812a50b94e9065e724a7f82afd8055da168a3c76facc64696915edf8dd5d99c
79a42767262547585dada08d033f
ProofRandomScalar = 4dab20fd864de6ceab345e8d755997956ddd1f267a2d8617
5aeae5e1168932285a6f602b4b20a570a697452b3ddbb7d0e29363ad3a6fed19
Output = 3733bc615577d0b4ee421030e42fafc45c07943dab1309ce5c93b7fd753
b54b8d4b9770710c2a0799031599f3fc81f8fee7656a5b695bf3b1b2eafbfe03d32e
8
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 01229ee057507c3e53534ad9db9f6df6ce515d1b8017923b65cada199e93
6a623c8eb3bd08e9b3f6584a85e4ff26e9f869d30b6c1f5bf11b,da4e3069d3ed33e
f13a08c384d74f6dcaed32bb9448c02865efb17a32b82c7f06a9586c63b775932689
cb8215043bf2952776afbc6d9ab26
BlindedElement = 90bc0fdfeeeb43811c39afe42a4e97448e5e8494c2bf9522154
10d4147667f9bdc7c9e7db02a94a844ada03f834660e83ff4e052e23d0b7d,e633bf
3e0df4150bb0feaa524ab008f26b65006e9d04b299949dd44ea814c9d4b837473e3a
dff919202645557118463b0ca5798b1a12f3e0
EvaluationElement = daabac62aead1073267807ba3de327db4179e76bcde35d78
49f95509da874dfacfdf337d97e3926c18d9ce15159116820c2787de7759acb4,703
02c85e8508bc373b66229bf9d33d402da29d6e1ce88560e95be1dd1a0d4a138bcfdc
c2cc646edf8ec928582bf317c46bb2935fa5c72fa
Proof = 4c2766e84939813a635abdc861a13150eadfb00d49bedbfbe218a57771a6
aa5209d9ef5881561cf5ee69c2b14c3584a68a9b92b18f758830db0693796ecdfa74
87fba1b57cc0df317e72a630619a273e266d97b4c4e2c12336e3ffca3dc020691de7
007db2661e7f0e58299ed038d307
ProofRandomScalar = 4e278b9fbe31963bbdda1edc786e5fd0033feac1992c53a6
07d516a46251614940e76a2763b80683e5b789398710bdbc774d9221f74c7102
Output = 1ee014a35d6f9668f1c66b6003b04cf14d11f47019401954d40b80e4d67
82f47da616410953283932ea7baf281f7c8ce4fdc391ba5d7f1473612f0d3325a858
9,3733bc615577d0b4ee421030e42fafc45c07943dab1309ce5c93b7fd753b54b8d4
b9770710c2a0799031599f3fc81f8fee7656a5b695bf3b1b2eafbfe03d32e8
~~~

### POPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 4830949d85595c3de128f8487b04378f1ddb834cb013925b90ff461814fde
784d03f1b938fb1a421aa1e0f57c7236d98afc501ae52664935
pkSm = 70b5023ffb66a7ed4933354e67a21ceed1fb065341c4cde7f5ee9572a771c
63e0ffb03864277e3ea83422537400b92678f3c3d6cf940771e
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = c3b11cb03005ced988ae863bc6f3e8b59bbd1354548220e81cd0ffb6f9e4
ec2173870ae684f86b1c06e41ecdb9ef83429e58098b238c292d
BlindedElement = ce23c7d365058dc76f97adf83eb0c7baa4f27aea3ba1b015d0d
a3043afab3d84694f1d0f5dbb77cfb96873aade920218f5ec80e481584747
EvaluationElement = 20f6d205648f3fb8c3928c1c8e1280d337778c3cc4b997fd
c83f1c05d694a398d31f514754c8daf7ff6b0f4598c6388c8fab35b8f2971021
Proof = 11a9c5c5edb3462ce2f9b2cc35021bb5e080fbe73d52aa90d376151b6eec
5a540812937b25e54cd7cc257cacfaadf3c4ca8f14d0f18f410e28645d4776f9f546
566f5ccdd5989482c7c058b3d939f4ec7a13ca3f335c32674fdd7a6bbb7c5a253381
d7808d836aad88e543cfd3f7b417
ProofRandomScalar = 9e414ad5e6073d177a1f0b697d9efa2b60c984df38632f10
96f2bf292478118d78e9edabbe9ad22900ad84b1a2cdcb869c70c832589a471a
Output = d9e601db2d1d487a4a9efeb04905431ad62b95665a754167ff6132b01d5
7f0b42f0ede3b6269672d2403aed4eccc3dfaffc90ac2ec34f36c49e843c65fb69da
b
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 87c1563075086f0749e88205237f77416210747f2369383efbec7bf6c78a
77d5062b938e91fbc6ce569a4461a97bda32d0af163d4307bb22
BlindedElement = 14e74297bbe248bb6a56e72310c55cc3de98622adc7aede7fa9
89163456486e06909f990d046120571f7e787c5cd177480b769f51d240618
EvaluationElement = 8a8c752fa9120bfb2a65209a03c4a16ea7008aa4cd642428
d95a6c835520422381df1b007febf10618f80bb4f2df4028367c7af414a458ae
Proof = 4028ab77cb806b4e89a5fe3f086842aa6aee53b3229dc58fb76c42e095ea
f3e3fadcd4cf453eb48a49cc3cd6dcc7f0ecbf4d242a9770b53a179cb4f8d0773d73
3d5bd5dc989a81d0883b88bd9afcdfe725a7959ac05c36ab69e6a674d36d1904573e
e20d2133a55059a82389eba41c1e
ProofRandomScalar = 68481b589434b3b5b6c131de9e080e58e63ca9ce7d0c1bf8
1599e1a6292f2574e3a23e21d5bf79ecc75a16f7a77618bb9a9224c39cf90a18
Output = 72e281088c593d2aeb79675693afbcb96da302f137458c0508837a31ad3
83d5cc3966e8a400e9e1fd1083cee8788fc987b00aad5d2dd42825105ffa0a3f7829
6
~~~

## OPRF(P-256, SHA-256)

### OPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = c15d9e9ab36d495d9d62954db6aafe06d3edabf41600d58f9be0737af2719
e97
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77e
b20d
BlindedElement = 0214499fd6847222cfb6cb68db02121851b9ed884737541fddf
655798a2b22c9a2
EvaluationElement = 033da53f19a54644f8654d54ca9653400c499641237f974f
f1386246bea54488ab
Output = 8f381166039c2bccc200b5b8d20bad86482c8ea96dbc809c03e3bbc14fe
55b1a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 7b7f977a1fb71593281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf
539b
BlindedElement = 034c9497343f27a300bde18834dd02dc656af533111811a565c
ba0ff554d384dd0
EvaluationElement = 0231f254a80fecb4147250214d8980b3334cb5f9e51a98bc
4de28a7dc490bc8d8e
Output = a81a10e35185b020020782772631becdf6fb95bce9dbeb65d8a96d78a63
33d00
~~~

### VOPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 7f62054fcd598b5e023c08ef0f04e05e26867438d5e355e846c9d8788d5c7
a12
pkSm = 03d6c3f69cfa683418a533fc52143a377f166e571ae50581abcb97ffd4e71
24395
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 2c2059c25684e6ccea420f8d0c793f9f51171628f1d28bb7402ca4aea646
5e27
BlindedElement = 035f218c9109e2f9fda41525d02bf0637b76e821a11155b8cef
51c2f4143261124
EvaluationElement = 03204514c2190a84fa3297217aaad13c2eb52fd4a65bf317
9e3ed83d5f72f9e5e6
Proof = 86da4d857e624685f482d2c40878400bb039d8af7e953ba2dd15f285ac00
24d7df243d3108d4eaba18f6ec423e2f82c4c230782ca368c20ba4a2e3f2a43dcecd
ProofRandomScalar = 1b538ff23749be19e92df82df1acd3f606cc9faa9dc7ab25
1997738a3a232f36
Output = 841053744fa1047cc549eb87e52c7871c0263be330b97f347efd6118c65
9fc52
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 8b45f65717a40c38f671d326e196e8a21bf6cfd40327a95f1ccfc82a9f83
a75e
BlindedElement = 03552596458a0cd6656909d2b475306e1bc8a08363984d6bda1
546784501b5b068
EvaluationElement = 036e48e2ac6c1082bfec8bf27c6127af5273911224d4eb37
ed5fa1248bd11e0d10
Proof = 3f92b01fb1420d4c90668fa246bc5f3e0f6c51f8c5c8a172c299954c0ce4
02c30909de2f54bfd96c33f85be923cab22c4ed81d373802f1d8f930fdaa520af4c9
ProofRandomScalar = 3d35895f4cff282d86b2358d89a82ee6523eff8db014d9b8
b53ad7b0e149b094
Output = bab88e86647f9bb28144656f46cb15c1fcdcd64863b19f549444a8f4c1b
bc456
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 83705fcc9a39607288b935b0797ac6b3c4b2e848823ac9ae16b3a3b5816b
e035,644c8539857abe3a2022e9c9fd6a1695bbabe8add48bcd149ff3b840dc8a5d2
5
BlindedElement = 03cdccc126afb60535c4e75157cd8ec1431e169af693fdcff4d
5d77b64c5b586f7,0367169f69b1eff90261e7444049c6f2d08d6a218b21bbdbb7fc
8750a5a5ffd232
EvaluationElement = 020e05d0b35b911ce76e14fd4822eb7168ef7b45a1fd43d9
a05c3bb3c0ec8bf311,02b13b991b82468a1cdf8efd694d3f9e239540eb06a34bfe7
b192fdbe3276b41e9
Proof = c1b4654ddca99c1179ae25d87397b8344dec55d43813165ad2bd6335f44c
592d365409f729d2dd56f662b8b6990d79b3795557fb34af9069f72ec609b233ba90
ProofRandomScalar = 316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043ba
Output = 841053744fa1047cc549eb87e52c7871c0263be330b97f347efd6118c65
9fc52,bab88e86647f9bb28144656f46cb15c1fcdcd64863b19f549444a8f4c1bbc4
56
~~~

### POPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 89231532daa982e80bc6edbf822f3788f51d720ce2d1ddcd9ebe865ad8a6a
7ba
pkSm = 03f398bf384b63b0dc0dc6d95f6883be889081b06de287fc1457c38513dd6
dd282
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 0470f06169bee12cf47965b72a59946ca387966f5d8331eab82117c88bbd
91b9
BlindedElement = 02a9e77b7aa32172fd173e59a8a8a9c1e3c4f4b5528bc0592dc
21ab64772a3320d
EvaluationElement = 03447927d273a03bd642f773f00ddb4927f6efca1be3fa6f
5699fe871ae45bc5da
Proof = 5101376c0dce9d7d2a334b9caa3989d0313411c192e5d23b9e1978fdaad7
fa429179ebe0cb372fdb80461b590137668c6ebcf639148685823fbf4d93fa481556
ProofRandomScalar = 466f3c0a05741260040bc9f302a4fea13f1d8f2f6b92a02a
32d5eb06f81de797
Output = ac495a4bb68260ddfbdca5be8f952c87b80d334d0d42112d7d541cfd52e
3b924
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15c1b9ee1e66339439e3925cf8ce21ce8659f22523b6ce778bbd8f8b541b
e4be
BlindedElement = 02f6e5ffbaf4b8d98cd9b8a6a5243a3cd509afcf537712f21c6
28aa10ef52c4fb0
EvaluationElement = 0211857b11174bbd7cf43bbc3eff7b0b543bfc69fe305cde
095aecd2914e4cd82c
Proof = 41c60a16802ee4175562dc31258b1f1db01ff0fb41e59b292c9d1c7653ad
24ad70c69665397ba158e70bf062a354b0dc0da6d2757c0dee8f74bdc6c40b0d6db2
ProofRandomScalar = a1545e9aafbba6a90dc0d4094ba4283237211e139f306fc9
04c2d4fe4cc69c0b
Output = 5903c7a833cbb9b570e5bfa41314500cfd6bb5ac6bc0c86c77bb6dcd7b7
27648
~~~

## OPRF(P-384, SHA-384)

### OPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = b9ff42e68ef6f8eaa3b4d15d15ceb6f3f36b9dc332a3473d64840fc7b4462
6c6e70336bdecbe01d9c512b7e7d7e6af21
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 4dd65065273c5bd886c7f87ff8c5f39f90320718eff747e2482562df55c9
9bf9591cb0eab2a72d044c05ca2cc2ef9b61
BlindedElement = 02c4eb0f78b26dd471bfa6d8babb0936425667ee6bee5515513
25431a564b7a5bfdef110317b6b21453955c63681bb2a11
EvaluationElement = 025ee7d04e824e7ace179c10810e877574d617dd2ea39d63
c0dee43cb4e8bb30a22931eb809e440c23b32eb688eabbf753
Output = 384a2636e9d94e8b3d2fccf50e24f7042374fddc18629909e62216cade8
bcd07cc20829098e1e4ee82fe4504e414af2a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 55f951785ae22374dfc19eb96faba6382ec845097904db87240b9dd47b1e
487ec625f11a7ba2cc3de74c5078a81806f8
BlindedElement = 0334bfc4cf126b2caad4964447039346a3f2170608f6aff312e
deed6d186d6cd16e80a381cd3575b9561ae68c228fee4b8
EvaluationElement = 034ca2886907eca964946026858092367cffd5a2aab704df
b43f76979b23bc271c6bc20a0f6d9e4344e0153cc8d7ac9330
Output = e5a40969fa72c597e2aad0596252196580813ca5827256265ae0e40250e
fc6df5664708b211f0ddc98ac25c7fddf257f
~~~

### VOPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 42c4d1c15d27be015844404088967afe48c8ae96d4f00ce48e4d38ecabfb8
feb5b748de625cdf81ab076745d6211be95
pkSm = 0389ad5e50eebf9617ae3a5778e4f0665b56aa9066919e1fa5580d8dd781d
560824e0e78aae816af6eff8abe2ad0585a0d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 84580de0f95f8e06aa6f6663d48b1a4b998a539380ed73cafefa2709f67b
d38be70f0ffdc309b401029d3c6016057a8f
BlindedElement = 0394e2556115a7e830f55d56d141ccf3d85ae18169d8ee80c28
978ae1abc49fb4bf28e82f68413359312d38d2cedc55bf7
EvaluationElement = 03f1793d88d367b65f045a454221be7d96fac26985060e67
7c886ed61831bdeb974a6f9f7182badd25cc1e1ad98f83ee36
Proof = 1088b7b22ccd9d1c8ce2fe5f2c65b99cc72a9958931337cd75031af108a5
66860a1ebfb0f06f587c4660909b76535c9cdc5a6111cf80c4cf9bd67a4cd458d503
fac5c745ba3b2af10b12ad9e6ba9c18e851e67ba19fe64334b9169a2a30aa1f9
ProofRandomScalar = e17e559ca3ccd1944f9a70536c175f11a827452672b60d4e
9f89eba281046e2839dd2c7a98309b06dfe89ac0cdd6b747
Output = 55cbc8c78c591a17a060f6ed462cf937826aed2df2e90726cf5ed55ef15
1eeaeef18787f83746becc45c6c9362217ccb
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 7759061965a423d9d3d6e1e1006dc8984ad28a4c93ecfc36fc2171046b3c
4284855cfa2434ed98db9e68a597db2c1473
BlindedElement = 022a802b27e6f6468b5f8ff12a9e10e971b55f5f80c2967cebe
6cf3a22c6c5350cc3b8a6fd7262d4f601946e18c827dae4
EvaluationElement = 03e6dbab214ad5c46bee8afb4037bca733cd7f8b8ca5eb99
7143d9e54d38b75717a2a8252e499229db1e66ab3afa49ecbc
Proof = c40c8593cef82cbe34f3d7bd958fc62c1f8114b4cc6a13f75f26a226c4f3
388840b92a63155ae1c2dd76031ed4d6b84f009115f8e53be5d7deee036451008206
663d18ec7e320420cd55ab91bfc3bfea0988ee6fb7096618e4c3785bd152d0be
ProofRandomScalar = f96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd1fa7
6e953a630772f68b53baade9962d164565d8c0e3a1ba1a34
Output = cb2f35d45de582607d124d0789525e6dedf0bcfc6b380059f8ce393a70c
83d2c2a2bafe6fda8682faedd49bfb9f1876a
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 563b3420d7764097502850c445ccd86e2d20d7e4ec77617a423883574303
7876080d2e3e27bc3ce7b5fb6a1107ffedeb,4ecbc087302667fabefa647b1766acc
b7c82a46aa3fc6caecbb9e935f0bfb00ea27eb2359bb3b4ef3d5c65b55a1b8961
BlindedElement = 02fc9fc91ac7fee2f806445b45013a4a0464749d81750be4aea
300e4903d0e838e1c3c2e9182e8174b200df65392ddc47a,02ea354e2b7b46186577
390d16bb2af526e3b77340fb830f37356c4a0aa234400bc629ebcf030744e02ab611
4ca15b9150
EvaluationElement = 03b6175ddf3c2683d98057289675fb04ceadb16df5d4cfaf
758b5c3a9b552930d5a9eabe983ffc3bbcdbe669f7607beb20,03a73e4add28824c4
d49e66fab3c2a97724eba6a46ec80c69864bd59b03aab9e06dccb56d03cfb276669b
1a72ccec5e635
Proof = 50be7cfdb22eb8d54282963abf1bfd30edad959501bf2f2609fea39c1736
5b0d5e0843e2a1ea8f5e38ac90e051a605bf150774b04d370619bba077f7b9fcb1c6
dc2b799e6bf739e70fe94b3499d26b079dfc9c18d08fa412b5e9d8e3bb83dc3c
ProofRandomScalar = f77ff0b2ebcfe21e1a1ca4a84361e9f1b18e24c9a40ed5ee
c262bf51dc970d63acb5ab74318e54223c759e9747f59c0e
Output = 55cbc8c78c591a17a060f6ed462cf937826aed2df2e90726cf5ed55ef15
1eeaeef18787f83746becc45c6c9362217ccb,cb2f35d45de582607d124d0789525e
6dedf0bcfc6b380059f8ce393a70c83d2c2a2bafe6fda8682faedd49bfb9f1876a
~~~

### POPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = e3e8a7602b17a19cc91711ec7df8ab913fcd3d429e769be6bed57755cc6b4
1bef922d8d5b85188a724c47bdac1ceae60
pkSm = 037c6bf0f50bff1d04e5bd84b785f93f451bf234671dca7c0eafbac65b521
eafd561c9e4fcec7ae4fc0db834a5ae96ad19
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = c405a354e666f086fa0ea4754fb56527be010296ea880e1c6a4dbbc9ede5
43a2ad0f83fd60fdacb59801a9d83b5d1c10
BlindedElement = 02fc60f6dbc6f262fc96f4b3cfd464f967eeb143f42630aeffd
8a89a51af29a4ee913899f1c43b8eada345126fa7291fbb
EvaluationElement = 02412293c3a7d3a627b2db807acac6ab6dc04fc8a8f969c0
ebe50045c5b43d71906c1c88410dc5c240719fe8bf23b2a49a
Proof = 26abd7694b2fbfcca2fba9f4d0b3c2f689e1313ca310f7aad54bb578363e
af90887823c17b284862cb4ddb930cbfb272364ea80ba1121ee13615f05aabf45265
f172fbc95a152ad85ed0436c0668cf1d7fecdbb0db3d1443a213c6c2b6acebe6
ProofRandomScalar = 5cf7fa02f3ad744eb5baf418275e45ab31ade30669dbae98
fb0879524fb9234e93a8bd048ad9f44b428026396a810329
Output = c34ba85a057257417181003752f09f0f2c42751d12d6d67780c9b409c24
dc08ca2a157495c298f7384917de4784d79e7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = fd762bff10c1b9bd5d37afc6f3644f8545b9a09a6d7a3073b3c9b3d78588
213957ea3a5dfd0f1fe3cda63dff3137c95a
BlindedElement = 025fe88056c51a118883f57fc066ebfd34d1c430b6ae63e807c
002a97137576077456d001cbdc1bae9ba913cd07704635e
EvaluationElement = 032de65f46a8476f2f1f42826ee2a56e0d7e90a25b4a8349
b6dbd1e63060dc4bd6a4b7fc2d552b04aa0c6c9f18954aa74f
Proof = ab6b2b24e51e46a6e4fa47446707515222a193291f58aee8900371603c52
6a31e294035a1b9b4a56c18e6cdf2660737f07b8f20969056455011fbff48b59a0e8
6ddb0ce976c296024170746b2bc6b8c8687bf3f1bbd789c92d71f9807c56fc56
ProofRandomScalar = ddff1365bb9b82b279e775b7220c673c782e351691bea820
6a6b6856c044df390ab5683964fc7aabf9e066cf04a050c5
Output = 7e670f82c19f9e132176f385b409749976ea7f8f227339014c583aae61d
5c0cb4b8bbe494e6e2c6a4a44bc67114ff680
~~~

## OPRF(P-521, SHA-512)

### OPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 00a2f8572ee764d2ec34363fb62ef9e8ff48883b5357b6802f43fffe5c5fd
0d11f766bf7086aab33e2dce02cc71d77250ef6ed360a3fd56244abb6bdbc3aa6534
da1
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 01583649f3e9cdf20a7e882066be571714f5db073555bc1bfebe1d50a04f
d6656a439cf465109653bf8e484c01c5f8516f98f3159b3fed13a409f5685928c72d
9dac
BlindedElement = 0201e96bd2ad4e61e68a78f1ff93cc06c392b9d20ecbe5b3d54
7b27a1c2d59839ed4c1824f8a2e5d42b2c5c60ec13df725b6fc3a48ff95a226beb63
e369d3e64caef9d
EvaluationElement = 0200932deeac097520701e773f35d920062da798445096ef
b5f54c586caea81e42c0fdc265b7731541a02d233f052c93a4474c99cb70f59a06aa
2d27fa94dd4d488ba5
Output = fa722b899acc3e46721122e5f8306feab7099f9b3a52bab0e60cb82b316
960e2e7d4c788df3f5fff6f2fbc61b6e293eea4d8ac7b1f316368b722f59deefe6ae
3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0017a273530dc66aa53bb9adb4f0ed499871eb81ae8c1af769a56d4fc42a
ef54a703503046d8272eaea47cfa963b696f07af04cbc6545ca16de56540574e2bc9
2535
BlindedElement = 0201d0be20c38601fad866c78c2caf7fbf2a1cb22a8cc5169a1
a989b8f058cc55d7435242aaf1dd373dfe232ae7327cf1f3d357fd367adbc4a2ee95
99af9d85b02afc8
EvaluationElement = 0201f1cd8d3166d928509842a25b0d836a8b2fcdde79a524
fc52a051fbb9e9227463ee809ec128a50314f8dc16f0a3a1327b062be539a67d9499
d49905bb7e864ea704
Output = ed867c7d004da03165cf299fb0886dc0d466ee8fde3b0e912cc2b8dbe13
e34fd82869118f1e501170cf8d4a2ecfb460cffa429dc5a66883d4a2eabaadf52bf3
e
~~~

### VOPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 0064799c2f9c0f9e6b9ac2aca5c42687cf15742fb73e086c4954aa0bdc8b8
25911ff03712e8d308c0a6ff5435375036f189391234bf21aac57fa73df155d70da4
7bd
pkSm = 03013e587a7750213bb7c2b338a4507635f1ba60ece346de32ad975373e56
fbabd878f9956996aac83a550ed5f5ba98fcc56817f6230cc7e84cb7eb2a1e1db51d
bfc1b
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 013a196708f773cf65852bda777210337d8b3b88754b881aa5fd937ec793
2e725ac43a07cb3ea0e90b40e0501e6bdc3c97510cdd9475ad6d9e630235ff21b634
bc66
BlindedElement = 0201cb841061f512b32bc297075fb06f149dad897ad465e6ba0
3ecdadd24966922a8f67d18df8cb62189c59973fe772debc0675408a7f678b14d090
ced5a61198ee5e0
EvaluationElement = 0200615889c13306edaa55c3098c5c7b0e49f58084eb461a
d823ef631389662edf818ed21202ea715006220d55b34d40d424e0b76f0a84780b71
595ede3a82adbb1524
Proof = 0058a9d238731f936ae1831bef6c16385f8354d69105476f4163719a2918
577d8161acff39ddd31ed62786de5d9f2e72b9885488e8e3db2c2f32331171603ac1
254801066362bd9345862b77569ba9df5f2c5514373c4075439105e9c3056c773334
dbc3d2908bf70ca78633673ced7be89dbeafbbb9bc234fa1ef3eb109e67fbd15d07f
ProofRandomScalar = 00eba4687426b0b4f35c14eb2477c52e1ffe177f193a485c
ccf5018abbf875b8e81c5ade0def4fe6fa8dfc15388367a60f23616cd1468dae6018
75f7dd570624d0af
Output = e8dd437f76b72e3dd93b52ab4c48a39de287d34181da998ce9ac848bd3a
51a82f5321b0afd774e1571a8dc64f4921befbdcd8c640b46574f197e970846a06e0
9
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0085f76f3320fdd24777894218769fc1965033654f34b06b578fe36ef23a
5b9872ade82b9261cc447670debcf78318add682f6055089b0a2484abc37f110b36f
4c2b
BlindedElement = 0301baa873c7209654d581f46fa3f2f4bdc4f423050e7c9a779
f4ccff0812c5acabc2fe940f39d280fa9a07316acfbfaeeabcdc520cd5e75cccedb1
adcd5078f9236a4
EvaluationElement = 03013d7a792ea82554b7aaf5b8f68dae350d6628ead48ee8
b15e376891e4dc94c286a857033083dc5752668d0a4c2751d0900575315bb4f7ffce
e58bd772e511baafc9
Proof = 001b1650ed1d8397822e5e3c67ec9865274745cb82c6d506da1bd1a6528d
e2fbe0f8b4a139b8478f1497b81d6295c11416725e165a3f2114ff128788b9352dbe
1c260063e71f8f7d3593016cccc9cfef640cf2b827edde47cdef204df11d1d546824
52ca77d2ed39eafe341b05ffb7846bb3b2704f2e5d2b9025f249d8cecde4d1ed170b
ProofRandomScalar = 0165aa02c8e46a9e48f3e2ee00241f9a75f3f7493200a8a6
05644334de4987fb60d9aaec15b54fc65ef1e10520556b43938fbf81d4fbc8c36d78
7161fa4f1e6cf4f9
Output = dc9f559b0f8ade51267eb596beb5577447230bdedbad1fcf65ba5297c7e
61567acb91ae0c50b54f905f7513c100281dfb2d40ece3a6f49849672f519fc80a4c
2
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 006915357a04fab501c0f6764e854701129e38071b008286c5fb629de5cf
ea56c0532dd8254a5a6e7fcc9e51e20a1cf4f254335ca57ce603ae7cf03fc00b7a2d
4953,00d60ce57aa6729d935ef02e2dd607cb7efcf4ae3bbac5ec43774e65a9980f6
48a5af772f5e7337fbeefbee276c901e6e57b7ec6752a45c74f3ed36a3eb8ad0dafb
7
BlindedElement = 0200112309d14634e5f0d453d1289f789d7014a90b021469e68
2026f411af0549ca3d46b22c46dc4c05ac9c3cac9755f394f3ee4374925d1f0395cf
b5611ffd7988b9a,02000f240c39d3ef3b03a08efa617eafd9605fdf40f483a9e8b5
f3ff31e9affe14812e4afa16939069070dc4467481f4557c6bf21f1da1fa706b5ed6
a9895093abcc5c
EvaluationElement = 02018ed97fea6e60f9f1719a628cbdf8dd655904e81c437f
7d9f0c0d818a690278bdc3f5c4f4448d51eb283e3d3dab757b618c8b926ba264507c
e19d5847d465adbcd9,030185ee868a085c6f2c1c2cbd989c7059eba50da416f86a9
3165b7412a7c1718820478857c48c1b8622eb0e10cb5d2b70f7a7d629d6303bd1d8e
811b8a7482289ded6
Proof = 0049b1869821825e2252ca695d66f0cc672738c07af70c2671be69f77c39
2b448902e8d2ea18e57c931d60ccfcbe875885dd46ed4960817006a6a02371953afa
4f2400faca7643c7ab6046294dfa2ac79853fe472d32767efac357d64aa9585b0282
1b367959610b6b5ea0b98f29c58c2f25cfa8d0bd7f8e683f9d78a6349de7320de190
ProofRandomScalar = 00ac8346e02cbdf55c95ef9b1aadda5ef280cfa46891dfa6
64a785675b2c95bbc2412ceae9d69a186038345f8ff704bc925f6818500615a825a9
a6b5646a4e4f11b2
Output = e8dd437f76b72e3dd93b52ab4c48a39de287d34181da998ce9ac848bd3a
51a82f5321b0afd774e1571a8dc64f4921befbdcd8c640b46574f197e970846a06e0
9,dc9f559b0f8ade51267eb596beb5577447230bdedbad1fcf65ba5297c7e61567ac
b91ae0c50b54f905f7513c100281dfb2d40ece3a6f49849672f519fc80a4c2
~~~

### POPRF Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 01bcad9924addf6a1595a49dd4e7c1981907e73ae6f9b60b0617140f788aa
9c16a236b198b2440f89baff014d405ca558d5d3ac50f1410dccf638bae6e4748cf9
c90
pkSm = 0301ad8d103addab07113823bb2d94932333a0fba8f94763371fc67d8db5e
e76006fe5b2f05e6a8d43fbb609a65b7a8c042f80162afbbec2d2fb1691a128efced
cf445
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 010204f2476ad5274e2f9d258659e80b0fbd20e4761b22298eba98ae9dc4
fcbc7ad42f5459d29f5c3b170f51d08e65679d984c1e852b2344bbebcb92747c83cd
6b89
BlindedElement = 0301fbaa2acd4b3c118aecd4001d521331b1d98cd45876c8c28
b37f6e38931abf8f6d7ef221ffaa89430817c0f51af0a3c82a5ae01e5afb76e912b7
13f095dd2ca2152
EvaluationElement = 02018ca1887998f2ec60a32b5b5d1be0f4b89a7bafa05046
25b0f12b97da2e969fc54ea06780a987a8196de459ff9c5e11630164a4ba3be3d329
7103dbd0a5cfdcbfbf
Proof = 00fc49339dac8fb334f1b4e1f22826aadf87c51345465d95ea0219ecaedc
e6b3a326a78099274726b722fab591798dc1f00c8b38561b14b9ae383c261e2dd4cc
1ef00141191342c6e78aa2be58c67e301fe81f2bdd25c60f26e321461541371af850
d78d85e47611fd1a22f119eaf86b81a7c36d04c496ec9a4a40a462fa2b189131061b
ProofRandomScalar = 008492e4dc9cd7f7aebfb1d3d2b8c7fa7904503aef20c694
a01d3e1154fe98e7232be9eaec5789a012a559367b1f99654ddef5acc7b0dbee75bc
d8bb50363ec64004
Output = bfc2e2c5dde3c65e22528b21459fafa625561dae539caa407c80bb49ba6
f8ba2195db945b92b889109ad74e57f796ede64d739dfaa7521d7bfbc0ae2a7518c2
0
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01ab3a90cc9da17604b2e59a93759eb0985d2259c20e3783be009527adf4
7f8fb5b1437cba7731c34ac70bc6ab1b8c14ff4110afc54c9598d5f1544830f9d667
b684
BlindedElement = 03005afd7be45866679f4d6407ffbae16df62ca61437487ef41
97963d0700ab9dde69bd326931261d533e16755b528b5ac7d6916bd37c49e76a3147
a3d91d3a9655d70
EvaluationElement = 0301d653352b885524b775116064c1de5fc1dedd1ca4ef80
560156d627f3ed71487a765ba4ea0aae4e659dc60997a2b362c6479ad5cda6fe8ac9
eb93ad8f1829f0858f
Proof = 0159601e267dca78265188a393cc0dd337451fb1bc530b2f8bf5a47f0ff8
49e310f0ae38ae704a66525bfbf9abdbd8499caa149baedf0553449ba8110564d8e4
01f900ea0554be32745571f50c3f83259b64f19046803c4cd7b577aae1349b50f024
06e9a77ef87c2511e2044b381442bffe64f7a0d210f364936f3f061010615309b7fc
ProofRandomScalar = 008c15ac9ea0f8380dcce04b4c70b85f82bd8d1806c3f85d
aa0e690689a7ed6faa65712283a076c4eaee988dcf39d6775f3feee6a4376b45efbc
57c5f087181c9f04
Output = 815428eebcd92bcbff8d4fbe87f3f279c73a7db234b35dc3a582aaccd2a
f1fdbb3a28c149fa1df3b87f02805cf0d72d6dccd63feef0021ac90b70523251ad05
4
~~~

