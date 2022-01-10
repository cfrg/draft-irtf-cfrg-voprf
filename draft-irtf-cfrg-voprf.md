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
in a Python-like pseudocode. The data types `PrivateInput` and `PublicInput`
are opaque byte strings of arbitrary length no larger than 2^13 octets.

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
The output is a value of type Proof, which is a tuple of two Scalar
values.

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

  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            "Challenge"

  c = GG.HashToScalar(h2Input)
  s = (r - c * k) mod p

  return [c, s]
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
              "Composite"
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
  c = proof[0]
  s = proof[1]

  t2 = ((s * A) + (c * B))
  t3 = ((s * M) + (c * Z))

  Bm = GG.SerializeElement(B)
  a0 = GG.SerializeElement(M)
  a1 = GG.SerializeElement(Z)
  a2 = GG.SerializeElement(t2)
  a3 = GG.SerializeElement(t3)

  h2Input = I2OSP(len(Bm), 2) || Bm ||
            I2OSP(len(a0), 2) || a0 ||
            I2OSP(len(a1), 2) || a1 ||
            I2OSP(len(a2), 2) || a2 ||
            I2OSP(len(a3), 2) || a3 ||
            "Challenge"

  expectedC = GG.HashToScalar(h2Input)

  return expectedC == c
~~~

The definition of `ComputeComposites` is given below.

~~~
ComputeComposites

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
              "Composite"
    di = GG.HashToScalar(h2Input)
    M = di * Cs[i] + M

  Z = k * M

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
    Client                                                  Server(skS)
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
the `Evaluate` function is the same key as it used to produce the server's public key, `pkS`,
which the client receives as input to the protocol. This proof does not reveal the server's
private key to the client. This interaction is shown below.

~~~
    Client(pkS)            <---- pkS ------                 Server(skS)
  ---------------------------------------------------------------------
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
    Client(pkS, info)        <---- pkS ------        Server(skS, info)
  ---------------------------------------------------------------------
  blind, blindedElement = Blind(input)

                             blindedElement
                               ---------->

               evaluatedElement, proof = Evaluate(blindedElement, info)

                         evaluatedElement, proof
                               <----------

  output = Finalize(input, blind, evaluatedElement,
                    blindedElement, proof, info)
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

The mode and ciphersuite ID values are combined to create a "context string"
used throughout the protocol with the following function:

~~~
def CreateContextString(mode, suiteID):
  return "VOPRF08-" || I2OSP(mode, 1) || I2OSP(suiteID, 2)
~~~

[[RFC editor: please change "VOPRF08" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

## Key Generation and Context Setup {#offline}

In the offline setup phase, both the client and server create a context used
for executing the online phase of the protocol after agreeing on a mode and
ciphersuite value suiteID. The server key pair (`skS`, `pkS`) is generated
using the following function, which accepts a randomly generated seed of length
`Ns` and optional public info string:

~~~
Input:

  opaque seed[Ns]
  PublicInput info

Output:

  Scalar skS
  Element pkS

Errors: DeriveKeyPairError

def DeriveKeyPair(seed, info):
  contextString = CreateContextString(mode, suiteID)
  deriveInput = seed || I2OSP(len(info), 2) || info
  counter = 0
  skS = 0
  while skS == 0:
    if counter > 255:
      raise DeriveKeyPairError
    skS = GG.HashToScalar(deriveInput || I2OSP(counter, 1),
                          DST = "DeriveKeyPair" || contextString)
    counter = counter + 1
  pkS = ScalarBaseMult(skS)
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
for each protocol variant. Throughout each description the following implicit
parameters are assumed to exist:

- GG, a prime-order group implementing the API described in {{pog}}.
- contextString, a domain separation tag constructed during context setup as created in {{offline}}.
- skS and pkS, the private and public keys configured for client and server in {{offline}}.

All protocol elements are serialized between client and server for transmission.
Specifically, values of type Element are transmitted as SerializedElement values,
and values of type Proof are serialized as the concatenation of two SerializedScalar
values. Deserializing these values may fail, in which case the protocol participant
MUST abort the protocol.

### OPRF Protocol {#oprf}

The OPRF protocol begins with the client blinding its input, as described
by the `Blind` function below.

~~~
Blind

Input:

  PrivateInput input

Output:

  Scalar blind
  Element blindedElement

def Blind(input):
  blind = GG.RandomScalar()
  P = GG.HashToGroup(input)
  blindedElement = blind * P

  return blind, blindedElement
~~~

Clients store `blind` locally, and sends `blindedElement` to the server for evaluation.
Upon receipt, servers process `blindedElement` using the `Evaluate` function described
below.

~~~
Finalize

Input:

  Element blindedElement

Output:

  Element evaluatedElement

Errors: DeserializeError

def Evaluate(blindedElement):
  evaluatedElement = skS * blindedElement
  return evaluatedElement
~~~

Servers send the output `evaluatedElement` to clients for processing. Recall that
servers may batch multiple client inputs to `Evaluate`.

Upon receipt of `evaluatedElement`, clients complete the OPRF evaluation using the
`Finalize` function described below.

~~~
Finalize

Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElement

Output:

  opaque output[Nh]

Errors: DeserializeError

def Finalize(input, blind, evaluatedElement):
  N = blind^(-1) * Z
  unblindedElement = GG.SerializeElement(N)

  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              "Finalize"
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

  Element blindedElement

Output:

  Element evaluatedElement
  Proof proof

Errors: DeserializeError

def Evaluate(blindedElement):
  evaluatedElement = skS * blindedElement
  proof = GenerateProof(skS, G, pkS, blindedElement, evaluatedElement)
  return evaluatedElement, proof
~~~

The server sends both `evaluatedElement` and `proof` back to the client.
Upon receipt, the client completes the VOPRF computation using the
`Finalize` function below.

~~~
Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElement
  Element blindedElement
  Proof proof

Output:

  opaque output[Nh]

Errors: VerifyError

def Finalize(input, blind, evaluatedElement, blindedElement, proof):
  if VerifyProof(G, pkS, blindedElement, evaluatedElement, proof) == false:
    raise VerifyError

  N = blind^(-1) * evaluatedElement
  unblindedElement = GG.SerializeElement(N)

  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              "Finalize"
  return Hash(hashInput)
~~~

### POPRF Protocol {#poprf}

The POPRF protocol begins with the client blinding its input, using the same
`Blind` function as in {{oprf}}. Clients store the output `blind` locally
and send `blindedElement` to the server for evaluation. Upon receipt,
servers compute an evaluated element and DLEQ proof using the following
`Evaluate` function.

~~~
Finalize

Input:

  Element blindedElement
  PublicInput info

Output:

  Element evaluatedElement
  Proof proof

Errors: DeserializeError, InverseError

def Evaluate(blindedElement, info):
  context = "Info" || I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)
  t = skS + m
  if t == 0:
    raise InverseError

  evaluatedElement = t^(-1) * blindedElement

  U = ScalarBaseMult(t)
  proof = GenerateProof(t, G, U, evaluatedElement, blindedElement)

  return evaluatedElement, proof
~~~

The server sends both `evaluatedElement` and `proof` back to the client.
Upon receipt, the client completes the VOPRF computation using the
`Finalize` function below.

~~~
Input:

  PrivateInput input
  Scalar blind
  Element evaluatedElement
  Element blindedElement
  Proof proof
  PublicInput info

Output:

  opaque output[Nh]

Errors: DeserializeError, InverseError

def Finalize(input, blind, evaluatedElement, blindedElement, proof, info):
  context = "Info" || I2OSP(len(info), 2) || info
  m = GG.HashToScalar(context)
  T = ScalarBaseMult(m)
  U = T + pkS
  if VerifyProof(G, U, evaluatedElement, blindedElement, proof) == false:
    raise VerifyError

  N = blind^(-1) * evaluatedElement
  unblindedElement = GG.SerializeElement(N)

  hashInput = I2OSP(len(input), 2) || input ||
              I2OSP(len(info), 2) || info ||
              I2OSP(len(unblindedElement), 2) || unblindedElement ||
              "Finalize"
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

This section describes considerations for applications, including external interface
recommendations, explicit error treatment, and public input representation for the
POPRF protocol variant.

## External Interface Recommendations

The protocol functions in {{online}} are specified in terms of prime-order group
Elements and Scalars. However, applications can treat these as internal functions,
and instead expose interfaces that operate in terms of wire format messages.

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

#### Q-Strong-DH Oracle {#qsdh}

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
Output = fd3b3e1424c876a811a3558ea27eef69a23b16b1e26997a8c5980e719ea
a9155a730a4680a09e91e9590a875a7d6a3667867da174e8d43b550d7792b0005315
8
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
Output = 4601db3454cdbae31c66922d3afaaae689899af378f5ca34183332ad9d8
aa217f25980a421e97f548b12a3dc59d69dda3713fdf8ec51ae8c6428cf328398cda
2
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
Proof = c256db421a3286a543b814ff2910659ffc84014cd807bcbd15046fc26388
060b931480a56967d5fb0398694542fe0bb0a1953332021fee378e90d394ba683a0f
ProofRandomScalar = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9d
bcec831b8c681a09
Output = 0925637f605f2da4cb5424cf810071c3343ff281229c0afa01826958207
8c93c23e530ba462f3817a6e8ab58580a995aa990f844ef84993b539a170a4384edc
3
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
Proof = 63eab55e660427fd36db9f2931aa27515bcd86d4bf77c609095318774f97
6407bc358b3d2d02d52387076dc3bde52e3a600514455d27a39a88b040d7b7746303
ProofRandomScalar = 74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df
9d013f7d6c312a0b
Output = 89b51fc800c79e249c3149477d28a00ada5ee894e470b9171223162260b
268affb1082713cf8d3ac381bd750df712623949c83de974854e39c5df90bf396ebf
f
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
Proof = 91cf0cbac5565c805580a210684d0849302326fa39cd22a4099ff1ccb9ba
34052251b656a5b6ac68a6c3057b1c379690e0a2e9b4a6bfa341e8b405013792f505
ProofRandomScalar = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186
a9706137886dce08
Output = 0925637f605f2da4cb5424cf810071c3343ff281229c0afa01826958207
8c93c23e530ba462f3817a6e8ab58580a995aa990f844ef84993b539a170a4384edc
3,89b51fc800c79e249c3149477d28a00ada5ee894e470b9171223162260b268affb
1082713cf8d3ac381bd750df712623949c83de974854e39c5df90bf396ebff
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
EvaluationElement = eeb704f4e05fd2bdbc189ca22ef025538165ef4839289886
f1f9d83ae61e417b
Proof = 4a4e7fbb5b0e8b94ab362b76e59b2eb7e686e679a61bf598046ece310aea
2f0f863527afef744747554e223c1505201b3a2c2ec28eeb72989a0f11eda2c2fc0f
ProofRandomScalar = 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6ca5b9
14b335512fe70508
Output = 342dc80a0fc56b34d0d0b0e96df8febadb7d1d7782472381f0fc3571061
5819d3ca993587b89603c250f04c8ebcbd48c8fd755ce14deef9f42ec05b20b60f27
3
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = de2e98f422bf7b99be19f7da7cac62f1599d35a225ec6340149a0aaff310
2003
BlindedElement = aad45f3d7d66884129d3048614dcd3e35bb0fbac66f073b916b
8ab66c7252249
EvaluationElement = b60ce5f6d855837c1947fd118c83dba5ad154b18afccc685
24e8ebcf4fb17e0a
Proof = cf72c646650cf8b140a44de8ff4f4b619dffa23b8bf44e60370b71190ae4
c909f53e4750ef76d9968b285c66c44a8d771d765a05b7930ec83410849b7875d302
ProofRandomScalar = c4d002aa4cfcf281657cf36fe562bc60d9133e0e72a74432
f685b2b6a4b42a0c
Output = 86cec51f8290fafa6523f770709d901d8c5efec3e2aedfa002b13694ddf
13ec1fc313cbdf94b019241d926c664ca995f81d9e47516f2e978a0933dbad03e793
1
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
Output = 0cf3d2c8bea99633af7e50b4dfd04a205d77f5a27da0acd4a3cf4284160
bb385ab01075928cc7c9355eedde4e29eb51a9e845a83927995e18e392d8f3858f8e
b
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
Output = 8765cfbfec353309dae15200f5ece075b5d11a2329d4d085917c1aa7b35
116e46e45ada7c495336714548bf31d57833737393f7e1fb97e4403bc052063ba06e
6
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
Proof = f5e94c46ade56ad071f3272ddc08cc349feda48c0e01403d74486886221c
2c1dae2da1cc645445a8ac6dcd1b0597df9315073e7dbb80632718fea9a9ba85273b
4f634e722e105c98669a051c5b9f058f5f07db6a6896b137c35bed3e093ceb418cb2
7919ec23032825653ec74f029306
ProofRandomScalar = da3e9faf0f2009d16c797646097d761e2b84e0df5d76ece5
658b3aab5207735beb86c5379228da260159dc24f7c5c2483a81aff8f6ff991b
Output = 0476bea0b5af32e5c4acf713dee317efd4124b2fc0f2ce90f15120d9e1e
2ed8c75b9abcc1cb238290b85bef86231938bac0abeea9a006e6ced003ca3b4265e0
c
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
Proof = 4cd3f93cba5a21d646b9cf33926973ad62f39f104d8da6571c33101ff2b1
8c469cd276d2f7a7648a7f6e9ee01127eec886594b532d3f6a0e7ce81c3561b51426
a9a0a3646e5f95230fd42aed5a6086b5f0ce2081688e2439e80b998cd59dd17f7150
9d657109fbf1882be12c4f638c09
ProofRandomScalar = 4dab20fd864de6ceab345e8d755997956ddd1f267a2d8617
5aeae5e1168932285a6f602b4b20a570a697452b3ddbb7d0e29363ad3a6fed19
Output = 9e4b68269cd8d3e8cf2d87ef9cff1e07c4ec02aff316d412fc6d867b775
ed325043175bca9190ec15a493aa457c5d17f5ef594b22f8e8b46a1a878636f0b253
5
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
Proof = bbdbd15fecd7ca234abdcb01a7fb02ee6cc219f75ab5b624833bec952bbc
707b655f4d13cb6b86ab539b1bb54c66a9475fa3ce2a0f01b8182d3135b1c1f9278e
22531ec469dc1b29103ac62aa35265b5c55690183cc60e784dfb28b6310a23ea8335
e0c09c5848e5506ae47676dc3401
ProofRandomScalar = 4e278b9fbe31963bbdda1edc786e5fd0033feac1992c53a6
07d516a46251614940e76a2763b80683e5b789398710bdbc774d9221f74c7102
Output = 0476bea0b5af32e5c4acf713dee317efd4124b2fc0f2ce90f15120d9e1e
2ed8c75b9abcc1cb238290b85bef86231938bac0abeea9a006e6ced003ca3b4265e0
c,9e4b68269cd8d3e8cf2d87ef9cff1e07c4ec02aff316d412fc6d867b775ed32504
3175bca9190ec15a493aa457c5d17f5ef594b22f8e8b46a1a878636f0b2535
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
EvaluationElement = 26ce331ad4a51a983b5091ab5ec5bcbc37d8622b0f0ed7cf
be123c474c004fe609cab847657de9e835a2c58e714f29d15d7243dbe964e695
Proof = 52db3e4c2031e3df29426791407bc35edae93192b59da99cbd65cfced416
1cb96f40744d036529d58b5e308dac21f0c0b149ab4c2eee583e26ad06717c3788a1
51256ae6c32596570991b97c3ee1d537b9d7d10978d5ead25f29b59a6f28bc3aa134
4623edce6050feb62d5d27b60a08
ProofRandomScalar = 9e414ad5e6073d177a1f0b697d9efa2b60c984df38632f10
96f2bf292478118d78e9edabbe9ad22900ad84b1a2cdcb869c70c832589a471a
Output = 1a593b2c934acc3d504e834a73276831ce7441f93ca7552adb0c45b18af
222a3e45c936a2c3a64702de43e570c0bfca194d00fefd23f15d12f0c49fe1d1a918
6
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 87c1563075086f0749e88205237f77416210747f2369383efbec7bf6c78a
77d5062b938e91fbc6ce569a4461a97bda32d0af163d4307bb22
BlindedElement = 14e74297bbe248bb6a56e72310c55cc3de98622adc7aede7fa9
89163456486e06909f990d046120571f7e787c5cd177480b769f51d240618
EvaluationElement = aa1c671697ba9b91adca349ec2174a75532187e992a64a8f
0dc4b5b8df6e26727e547032d3ae9d482da346a4d839a68544f9b8f96bd526e2
Proof = 56674fe3522f9e46f92c850829bb0f6147d96cd03f4725a0e4ea6b53ff47
e28f19c7452e4b6ecc746507f7f9eec70e49e5a081b998b022136b700068375a63e1
f861c71fc458fa891115212c90acf7a1030db303402ab8a5e8e842fee81452c19072
a0005916ace140ceb51197fcf23e
ProofRandomScalar = 68481b589434b3b5b6c131de9e080e58e63ca9ce7d0c1bf8
1599e1a6292f2574e3a23e21d5bf79ecc75a16f7a77618bb9a9224c39cf90a18
Output = ddd1d28bc5516c85d4d0202e5904a2a92586cd8c0f26ed20393c5bcf70b
15aa33938bc3179614367105730419f5fb0d495079cf2e8b84b70170e964bae4f12a
0
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
Output = bee89c9d383f4ffc5d43b2b8efd185428366d26580a3597fa6f4a6b069f
17ac1
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
Output = 3284ba954ff6dd0c1fa2e2e8b1d52d17fbf7e52f3d0cfa894344253516d
67eea
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
Proof = 754781f357918661054f8b39011e995412772fda58c2f0eaab488abd0185
3d046d434702e59b9ddadefc4c0cc94e32894ed78e63331af60241344184ac82706f
ProofRandomScalar = 1b538ff23749be19e92df82df1acd3f606cc9faa9dc7ab25
1997738a3a232f36
Output = 45aa32847b1ce094c060d37664937866308f007170c9aac2a943d103e94
d0004
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
Proof = 65d0c25f226bb260e01134e4197cb077fb9a43a62a702655cd518a1e2c74
3decf8b59f4ad3048bc36dfc88a18e571bb3934ba78a0933c3a15538772e1f43a87f
ProofRandomScalar = 3d35895f4cff282d86b2358d89a82ee6523eff8db014d9b8
b53ad7b0e149b094
Output = 3e3c5c10845bff573c040333be9c83440cc888456c63d82722127844315
97f39
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
Proof = 1540451231eb093d0fd42a786ab3a12f3c647d2ce26550b6849481930def
eaafd21e0876b029660ebe31d025a6ffb6e26171905c0d3ebed9d4a4d8615e1a65c9
ProofRandomScalar = 316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043ba
Output = 45aa32847b1ce094c060d37664937866308f007170c9aac2a943d103e94
d0004,3e3c5c10845bff573c040333be9c83440cc888456c63d8272212784431597f
39
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
EvaluationElement = 02293297df91b01e1f75a702f2673eeb435797cfa4a8afb5
86061e3b9245127ed1
Proof = 2e2f27608ae61cd6d21126faef15678d8a3294aa57f43ad11ae8af6ad169
4bb4a4e8a82a561e6526d6bf501be5f3bd7a52131fd5e4868af26a4d1838b5fc75f4
ProofRandomScalar = 466f3c0a05741260040bc9f302a4fea13f1d8f2f6b92a02a
32d5eb06f81de797
Output = b8808e10e23cfd422ee86673ff8c094cc347e604cfd91c8b055394eb3d6
c72cf
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15c1b9ee1e66339439e3925cf8ce21ce8659f22523b6ce778bbd8f8b541b
e4be
BlindedElement = 02f6e5ffbaf4b8d98cd9b8a6a5243a3cd509afcf537712f21c6
28aa10ef52c4fb0
EvaluationElement = 023d1df31312cb5b72728679783ee4a019b6d0d28726d9ac
7584de458f5090cba4
Proof = e5377709734c881ae0c3376cff9854886a0f5e7eda54a379f7ced0874575
6f47915e9d674e8a270902b06e421f1366f9066a84e562c8424c74a2b2312393611c
ProofRandomScalar = a1545e9aafbba6a90dc0d4094ba4283237211e139f306fc9
04c2d4fe4cc69c0b
Output = dcb2405478265bfd9833e3eda76d5a228c6354076c3366e9a865782e130
e7e68
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
Output = 149f664b38ea596fd55517bd3add0094f152bf6166e7192b9e72a875feb
37ff24ba2b8eaa15fac9191e390927e2bae8a
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
Output = a18c3d46c55d98ff9b07f8015a684e32e57162d236013116692f1b03887
d58885a08a932509b5e9c0ae3203b2d875e55
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
Proof = 5ba5dc21d4d9146189014b29bc2fcb062e4b7496112c38073c626f9650ba
cf18ec4cb30c0d47313d7429d07a6eda23169c879d228084571f17bccda2302bd52b
cf550be6965f72067a6dd746ea5858370da787a1ca1831f721340bc4c5ae8e5d
ProofRandomScalar = e17e559ca3ccd1944f9a70536c175f11a827452672b60d4e
9f89eba281046e2839dd2c7a98309b06dfe89ac0cdd6b747
Output = a5f4f2fd35205d1e4dc2769d009e51553b1655377a6cd5e8713f3ee9aa2
07f5afefc9649375e0b472ede4ac0b68b0bbf
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
Proof = cac8b6fa5c126d0cb254852cf6b4f4e126d2dcf78788ba66ed251708e0a1
ed3f173f29eff7d0e0a97fc73fa050d2e2d86eb6e0757bbee6f9ac2235c244ab6c6a
dd0b6de46af7a14afc0f83484804e5db61f0a70b8640ad585cd7740fcbcbbce4
ProofRandomScalar = f96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd1fa7
6e953a630772f68b53baade9962d164565d8c0e3a1ba1a34
Output = aa304f11d0d2f221412c65db6684fdc051fed3d2eb626461a4dbdfb2218
0f6238c05045d39d100379fe873611191abff
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
Proof = 4a2a01f086865f14d7ccac57fc8a3128eaae72424349c23b38985c4e6765
a83762e533b1d30c4cdc8e0b316a5102d97cde463bde0dda39046bceadf6cd6838a1
0df63fc99876c657e19a3cddcad19d3c30c8764f93d8801d9289ae9b9ad77536
ProofRandomScalar = f77ff0b2ebcfe21e1a1ca4a84361e9f1b18e24c9a40ed5ee
c262bf51dc970d63acb5ab74318e54223c759e9747f59c0e
Output = a5f4f2fd35205d1e4dc2769d009e51553b1655377a6cd5e8713f3ee9aa2
07f5afefc9649375e0b472ede4ac0b68b0bbf,aa304f11d0d2f221412c65db6684fd
c051fed3d2eb626461a4dbdfb22180f6238c05045d39d100379fe873611191abff
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
EvaluationElement = 026ca0ee64813ee656e96ab14fd8056842d79e9a13047410
3778d15d25fa817e8adf1d4c68afea81f2dc97d393d1f8a150
Proof = e2046f0d64cb43f38b2a406e42b79df6d51fa6124e47249a15826c09b7fc
596b6904c418e8fd53d30524347a6a9e37b3eedb4b1e9963c77a048773a4718b8aa5
3ee7499ec8fa08f44a4c31c12aaafc913f467c1c7e647cf55dc225fb74376600
ProofRandomScalar = 5cf7fa02f3ad744eb5baf418275e45ab31ade30669dbae98
fb0879524fb9234e93a8bd048ad9f44b428026396a810329
Output = f65c4bd1b4e659de5fecc965408a9b1db0f8a86bffc3b2b031935f5d785
f54ab85d3c121a95d85c8528eb0ac23c213de
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = fd762bff10c1b9bd5d37afc6f3644f8545b9a09a6d7a3073b3c9b3d78588
213957ea3a5dfd0f1fe3cda63dff3137c95a
BlindedElement = 025fe88056c51a118883f57fc066ebfd34d1c430b6ae63e807c
002a97137576077456d001cbdc1bae9ba913cd07704635e
EvaluationElement = 03c46510ab68ac6e3da5cc2b7b8956a9626ac1e09548f1f5
541828d1a77ed47aeb325d50c0c5ee8ac1ce6a7b5a28665752
Proof = ea36521cb51388b831aa068a7723836b97b43b59ce4a6472b3e0debacf0f
8b3f2fde560631e9d7dd043c16ac6238d5d448bc5c646d3089e747341992e4c18706
c7e3d67b4ec0f950f7adc3c757964eecb97c24d9573dcef5494a38d4912a0132
ProofRandomScalar = ddff1365bb9b82b279e775b7220c673c782e351691bea820
6a6b6856c044df390ab5683964fc7aabf9e066cf04a050c5
Output = 27ad157602b0a582e83995a9ec7059ba16a25cd5a480a4b47780646426e
0994cc40b2a833d3188df95ea4d96f6501a28
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
Output = e5457f91608af4fa340c960087b6a570a379dfe2677f6735e1a789561b1
882acada9bee13f731a3e9052027175acbf8f051e60afe2499ccbdc547fba17b4e0a
8
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
Output = f7d7f6f946f5fc678bb0e5ae814f06ca81a2e180c5695ded9966350b48b
6ce58c0f7cd30bf102bf93f65896aa7a385775e1e184bc104197398d0edf7a0c5706
2
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
Proof = 00300fe79f906744bfd91c93f8cf96e1db1210eacea7b7b9389403151131
96fbd633fab72feccdb580b6b48dc8f4125bfb4f6b2a694fe2a9cddf2740982c6d0e
70f901d835d849a4365d0f866b4ee4ac084552c127327e2b6b9c34de23e7103a1b25
63cea378851e97883c86694930892c1b791a47ce427d4823f311c5b937938e19d01a
ProofRandomScalar = 00eba4687426b0b4f35c14eb2477c52e1ffe177f193a485c
ccf5018abbf875b8e81c5ade0def4fe6fa8dfc15388367a60f23616cd1468dae6018
75f7dd570624d0af
Output = 1ef9dbce08fcdce60694987e1853fcbc54f0206effafc7bad17cd4d6784
c4ad40ed50d74696037b874f5034616633c2c243e066de3b702e9e6568f495121afa
7
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
Proof = 00c3ef9529360f7774e9537a2b3b1ff38c70345bdc07269d2e5a62e0b592
15048b198ac0b8ada686c45bb578abf6db26a04c7ce27d1fcd565c23939a5bfd6189
074000e6db3e5b9b1cd8d9ec0acdb92598511c4cbe7e62a6666b9c6930a8e91fa7b1
50a67e50659e78d7175c5becf5cd0f1707e72fefe9870f725a7e5a2c2ffd9ad620f9
ProofRandomScalar = 0165aa02c8e46a9e48f3e2ee00241f9a75f3f7493200a8a6
05644334de4987fb60d9aaec15b54fc65ef1e10520556b43938fbf81d4fbc8c36d78
7161fa4f1e6cf4f9
Output = 3ae6563392a94882e77a352e3d75bb49f6d14a2af31ff9c552f869fe1af
f02d9c533d820f7d88fe741d9c4ba1a2eba8fc5576d551c4cc90e9e61d568e1b6606
f
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
Proof = 003d598f1725882369d61baf214e1a97d8ae24cc9af53f988e1ed9c53f6c
ff9809e4faeca94e37c1252aa82deeb01e8eaba41e684ef9c9266377dd1376b273c0
2a850083208d6ef64434309c9c1886f7237b52f6bed77ea09b08eafc2dee5cd3e6d9
621ca9919ea8fb81b6a35e7b8e164a996a658a371a54941e93cd66b3104926c877ad
ProofRandomScalar = 00ac8346e02cbdf55c95ef9b1aadda5ef280cfa46891dfa6
64a785675b2c95bbc2412ceae9d69a186038345f8ff704bc925f6818500615a825a9
a6b5646a4e4f11b2
Output = 1ef9dbce08fcdce60694987e1853fcbc54f0206effafc7bad17cd4d6784
c4ad40ed50d74696037b874f5034616633c2c243e066de3b702e9e6568f495121afa
7,3ae6563392a94882e77a352e3d75bb49f6d14a2af31ff9c552f869fe1aff02d9c5
33d820f7d88fe741d9c4ba1a2eba8fc5576d551c4cc90e9e61d568e1b6606f
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
EvaluationElement = 0301a3c4026901a007748bbcfb523b9f79aa440fd91cbd94
cd73969c24ab3e1fc430d62154a5daf69cc8c2460bef7b5d52472d3bbccfd3223680
0b0a183282e3c22b39
Proof = 00f7f0c58660ae95ba6f1c003fb9fed5fa903f783b38e5bf475d009a983d
155e15be26459fb07313cbd6b258f28f632cda32795cd5f864cc226078e529b6b91c
af2400b471bf4ebc39f736a28f3d848e3e4855f7cdf7b32653312a45876ea99e6404
cff16fd7a2b1cc2997190e57d0e26789032cbc8586c0504fb43fcf84994d57d1c022
ProofRandomScalar = 008492e4dc9cd7f7aebfb1d3d2b8c7fa7904503aef20c694
a01d3e1154fe98e7232be9eaec5789a012a559367b1f99654ddef5acc7b0dbee75bc
d8bb50363ec64004
Output = 7b25727d6e7231868a093467a35cd5f650c4e7119a659c17c75713a3caa
fd19172b9dd1c52e19fcfc031a32b386f0106632dfd3b6de1e1499268898391e26aa
a
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
EvaluationElement = 0301b8d76cb194d5207a64e78a2afabea357d5743f6dbf9b
b3dac0e666274fd833dae0ba21007c5c2d7a2032abccaae8ed2e44a1523b4f8ad205
f25dbad557de3fe212
Proof = 0031f81bc53f787f10368cbd02866a14e603e6be28a6077ac7fb35db1ac5
ae376b207bb213e07cd1f4c0ce1de5cfef06eb3f1c07bf3ad936ed3188b210f39ae1
d88e00f74abd90511bfbc99a3bfd3d438824881316fc5bb3861e6bb65e31c9f47687
49b1aab065605fc460313debadf6530aabd78fd8fe2246b57579a38e8de623f98581
ProofRandomScalar = 008c15ac9ea0f8380dcce04b4c70b85f82bd8d1806c3f85d
aa0e690689a7ed6faa65712283a076c4eaee988dcf39d6775f3feee6a4376b45efbc
57c5f087181c9f04
Output = 34ec5a12c07a35a9f6acbcbd991a2552444c9255c30f63b0537e1d6ed07
1b736b732a88e40c368d8978e475ba0391865f608db1169c655697550f109589283c
3
~~~
