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
{{!I-D.davidson-pp-protocol}}. Verifiable POPRFs have also been used for
password-protected secret sharing schemes such as that of {{JKK14}}.

This document specifies OPRF, VOPRF, and POPRF protocols built upon
prime-order groups. The document describes each protocol variant,
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

- `Group`: A prime-order group implementing the API described below in {{pog}},
  with base point defined in the corresponding reference for each group.
  (See {{ciphersuites}} for these base points.)
- `Hash`: A cryptographic hash function whose output length is Nh bytes long.

{{ciphersuites}} specifies ciphersuites as combinations of `Group` and `Hash`.

## Prime-Order Group Dependency {#pog}

In this document, we assume the construction of an additive, prime-order
group `Group` for performing all mathematical operations. Such groups are
uniquely determined by the choice of the prime `p` that defines the
order of the group. (There may, however, exist different representations
of the group for a single `p`. {{ciphersuites}} lists specific groups which
indicate both order and representation.) We use `GF(p)` to represent the finite
field of order `p`. For the purpose of understanding and implementing this
document, we take `GF(p)` to be equal to the set of integers defined by
`{0, 1, ..., p-1}`.

The fundamental group operation is addition `+` with identity element
`I`. For any elements `A` and `B` of the group, `A + B = B + A` is
also a member of the group. Also, for any `A` in the group, there exists an element
`-A` such that `A + (-A) = (-A) + A = I`. Scalar multiplication is
equivalent to the repeated application of the group operation on an
element A with itself `r-1` times, this is denoted as `r*A = A + ... + A`.
For any element `A`, `p*A=I`. Scalar base multiplication is equivalent
to the repeated application of the group operation on the fixed group
generator with itself `r-1` times, and is denoted as `ScalarBaseMult(r)`.
The set of scalars corresponds to `GF(p)`. This document uses types
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
- ScalarInverse(s): Compute the multiplicative inverse of input Scalar `s`
  modulo the prime order of the group `p`.
- SerializeElement(A): A member function of `Group` that maps a group element `A`
  to a unique byte array `buf` of fixed length `Ne`. The output type of
  this function is `SerializedElement`.
- DeserializeElement(buf): A member function of `Group` that maps a byte array
  `buf` to a group element `A`, or fails if the input is not a valid
  byte representation of an element. This function can raise a
  DeserializeError if deserialization fails or `A` is the identity element
  of the group; see {{input-validation}}.
- SerializeScalar(s): A member function of `Group` that maps a scalar element `s`
  to a unique byte array `buf` of fixed length `Ns`. The output type of this
  function is `SerializedScalar`.
- DeserializeScalar(buf): A member function of `Group` that maps a byte array
  `buf` to a scalar `s`, or fails if the input is not a valid byte
  representation of a scalar. This function can raise a
  DeserializeError if deserialization fails; see {{input-validation}}.

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

Errors: DeserializeError

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
  blind, blindedElement, tweakedKey = Blind(input)

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
`Ns` and optional public info string.

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

Applications serialize protocol messages between client and server for transmission.
Specifically, values of type Element are serialized to SerializedElement values,
and values of type Proof are serialized as the concatenation of two SerializedScalar
values. Deserializing these values can fail, in which case the application MUST abort
the protocol with a `DeserializeError` failure.

Applications MUST check that input Element values received over the wire are not
the group identity element. This check is handled when deserializing Element values
using DeserializeElement; see {{input-validation}} for more information on input
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
  proof = GenerateProof(skS, G.Generator(), pkS, blindedElement, evaluatedElement)
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
  if VerifyProof(G.Generator(), pkS, blindedElement, evaluatedElement, proof) == false:
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
  proof = GenerateProof(t, G.Generator(), tweakedKey, evaluatedElement, blindedElement)

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

def Finalize(input, blind, evaluatedElement, blindedElement, proof, info, tweakedKey):
  if VerifyProof(G.Generator(), tweakedKey, evaluatedElement, blindedElement, proof) == false:
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

The DeserializeElement and DeserializeScalar functions instantiated for a
particular prime-order group corresponding to a ciphersuite MUST adhere
to the description in {{pog}}. This section describes how both DeserializeElement
and DeserializeScalar are implemented for all prime-order groups included
in the above ciphersuite list.

### DeserializeElement Validation

The DeserializeElement function attempts to recover a group element from an arbitrary
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
which returns false if the input is invalid. If this function returns false,
deserialization returns an error.

### DeserializeScalar Validation

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

## External Interface Recommendations

The protocol functions in {{online}} are specified in terms of prime-order group
Elements and Scalars. However, applications can treat these as internal functions,
and instead expose interfaces that operate in terms of wire format messages.

## Error Considerations {#errors}

Some OPRF variants specified in this document have fallible operations. For example, `Finalize`
and `Evaluate` can fail if any element received from the peer fails deserialization.
The explicit errors generated throughout this specification, along with the
conditions that lead to each error, are as follows:

- `InvalidInputError`: OPRF input deterministically maps to the group identity element; {{oprf}} and {{poprf}}.
- `VerifyError`: Verifiable OPRF proof verification failed; {{voprf}} and {{poprf}}.
- `DeserializeError`: Group element or scalar deserialization failure; {{pog}} and {{online}}.
- `InverseError`: A scalar is zero and has no inverse; {{pog}} and {{online}}.

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
input.

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
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = 8453ce4f98478a73faf24dd0c2e81d9a5e399171d2687cc258b
9e593623bde4d
EvaluationElement = 22bcfc0930ecddf4ada3f0cb421c8d6669576fc4fbbe24e1
8c94d0f36e767466
Output = 2765a7f9fa7e9d5440bbf1262dc1041277bed5f27fd27ee89662192a408
508bb8711559d5a5390560065b83b946ed7b433d0c1df09bd23871804ae78e4a4d21
5
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 86ef8baa01dd6cc34a067d2fc56cde51498a54cb0c30f63f083
53d912164d711
EvaluationElement = a27d5e498927ca96e493373a04e263115c31b918411df0ce
d382db4e66388766
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
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 444550ea064013c569fe63567eb93e7a9496902a573ea1e6654
76fd39d5edc40
EvaluationElement = 7af7a45e4f1e0c6d410d41704e16d980ebff051fd0975fce
cd17f79a6b57a473
Proof = 26982a26b2aa20f1e449be5a858c59d7992f7f4a13b007e3980f5c36e8ae
a7014268883db3094e08e3f493b3d23bae87ac098a33e775172c1027f1b5d025ca08
ProofRandomScalar = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9d
bcec831b8c681a09
Output = 453a358544b4e92bbc4625d08ffdde64c0dbc4f9b1501d548e3a6d8094b
a70a993c13a6e65a46880bbd65272ba54cf199577760815098e5e10cb951b1fc5b02
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = 82d9fc20daf67106ae2d2c584c615d103dafda653ac5b2b2c6f
aafc06e3f1c0a
EvaluationElement = 60c468920f4f949be9aaaf9b4fb27dc7bc89daca4a3aaa31
e96efae56c02ac75
Proof = 4a7490fd0a9e13cc66bcdeded002899a3e206364d9bdbaf9998a73dd728c
8602a6967f81a4948e6de797d638ee02ca44d933d05f2715fa1618b6a3324f3b2608
ProofRandomScalar = 74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df
9d013f7d6c312a0b
Output = a2bacfc82a4cac041edab1e1c0d0dc63f46631fb4886f8c395f0b184a9b
7cbbef2eee05bbd3f085552d8c80e77711b2ad9ba2b7574e2531591380e717d29c6f
5
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0
d50f,533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0
c
BlindedElement = 70a6ac589da4cfff4a1135c21e438a50935317ad6900810a59e
76c2c28d8e562,5ed4710468c94e6c0181aef8276204ec6aef509f5cf1d7d6184693
1481d23d76
EvaluationElement = 5ef7bc4c54aa5fccb4328fd725d3c20130ebe3ced54f28b6
e6c4591815158059,0ce1a236be8dba445cf57ddddec8f1c2d9be2c164add431fc18
e3279be968c2d
Proof = 53afba40c6c27636a0694def258728f192d25ec5f97ee1e87a408fd20615
6107d3b82b618242f10ff459d7d30d0a68d9e381254d2e5f6bc82671f093f47c0e01
ProofRandomScalar = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186
a9706137886dce08
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
Blind = 7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc1e9213a043b743b9
5800
BlindedElement = da01485047605a666542d0599ef2fbeed0c2e45a97c6e3d420f
832918e09f535
EvaluationElement = 3015fc16fe179bdb9054da5297c77d1f249dabf32e4fdcc4
937d6ba5e99d7b53
Proof = f10470180fc884a2f51472eddde9ad9a4080b00e13f63c130cece83b93ca
500f956b08e35ed2670ca504c704e0b74687451f5985627c93e2290a5da0dffc1d0b
ProofRandomScalar = 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6ca5b9
14b335512fe70508
Output = 4d04eccb77a29bd8a00fb1e3f391e0601340c3dc874fc7bb16cfd92d961
532d18b4edfffaec94457cb19111bca1ecd19e46124c6a5d29703d09df5e5ab521b2
8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = de2e98f422bf7b99be19f7da7cac62f1599d35a225ec6340149a0aaff310
2003
BlindedElement = 909f8d2d517fa2235f8b35f91220636732541d9f3e309c6988d
6d8c987e5a357
EvaluationElement = 241786b8f9da3e8c28d75dc23b5f8b251ec150ccb453efa7
12f6e9b72e763a0a
Proof = a3748b980aec81add561bcd7ac4fe2b09a93bd8a127991788fd618bf7fb7
93034a6f7f59cdcab538ed3e50d74b31f82dff14e3c8d3a081f744a6bdf93526ed0e
ProofRandomScalar = c4d002aa4cfcf281657cf36fe562bc60d9133e0e72a74432
f685b2b6a4b42a0c
Output = a88ab2bceba2c9c5a0ee0ee45636e65042b5f274af864f8c1560d32ecee
4373c31907f237609d3f164beec32e3270588961c1d19cee467d2a3b0445ebdea215
9
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
Blind = d3a425c41eac0e313a47e99d05df72c6e1d58e654a5ee9354b115060bca8
7db7d73e00cbb8559f84cb7a221b235b0950a0ab553f40bcc304
BlindedElement = 28791eab6c162e743fa0a9a36a2d23aa68674b2be1c32a68adf
c7e0ffc838ceb5275223e64306671c27a2091b7afd7ed79e42bed6bd2da78
EvaluationElement = 089919a875f4d30c7222335df3692a6b81133a56889ec99c
08cfe494dd08095fe2fa1657d02a44ce4700100d74a0a7d10f67e85a009265c3
Output = b93d3ed18489c1236cc965d202254de35767ea673560d6c225cec0b30fe
3adc88fee63f8a78d127cd64c7077e1d3ac4a7cc761335c0bcdc12d6981ad8730285
8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 87abe954011b7da62bb6599418ef90b5d4ea98cca1bcd65fa514f1894bcf
6a1c7cef33909b794fe6e69a642b20f4c9118febffaf9a5acc11
BlindedElement = a2d6d32c73a6841e6caa2b3f6ffc7a803c86ad1fc82956dd82d
e050588a4f4c2089b6790139d5db09bb4a9cfc77b4419f250cabc6cce0238
EvaluationElement = ce914519593d6e09f917f02e675c6ec1c7ba65d287a3347e
834585cf6d99008548f34f14bc318de6215964312ab02eeaa524d12dd8144264
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
Blind = 20e7794aa77ced123f07e56cc27de60b0ab106c0e1aac79e92dd2d051e90
efe4e2e093bc1e82b80e8cce6afa798ac214abffabac4a096005
BlindedElement = a0a185b48d91dc0df1d6e5c9d22f8e1438c91fba744577a8f01
b4d874aede303ac25318e6827464033544db2aa9e4ee130037c9b1c16f397
EvaluationElement = b4aefe671dc177eca469727479f7a3e6218198df97ad87d5
822a8237e61e68a49597c083ad566a3bd3d63d157930581975764d8226bb4f5c
Proof = bc0d7cf269b955793bc3d185264df51a22c209720253ff37a704f7d5d5cc
54fce087d76038f4e4cb07e638bd844fdb706ba4ba07d7219300da88e06d02f9ed39
d5c91d0ebe3c9a2fb49174a1c54ea219a9b87f26d7781e5079dca25c4a4951cedcc9
7151acc4a8d8d9a5d9a8d111af1e
ProofRandomScalar = da3e9faf0f2009d16c797646097d761e2b84e0df5d76ece5
658b3aab5207735beb86c5379228da260159dc24f7c5c2483a81aff8f6ff991b
Output = b558e37f6435a12fefded196936a4c1d0882bf4a115002920744ecb3128
43678f396f7d36711cf551750388ddf7a53a3aea7fd0ac60568cd2d4ead16a1ee106
f
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = befcb571168f337dd52851d4bc07947c858dc735e9e22aaf0576f161ab55
5182908dbd7947b1c988956fa73b17b373b72fd4e3c08992892a
BlindedElement = 6caa634ab200766b5132d8144b2e67f1d5f29573d42008be82c
870f184f7220479f5dd6b0b894b4c244afc050b6d3b5405cb18dc87393a8c
EvaluationElement = 1a6ea9611ecb4fb354adf935ba4d08b2ddc8b459459ca18a
2894af6964668f911c60d517286cef5397dc94b70f8785b15d342ddc411cb856
Proof = f0cb5b7f238147016663ba096dfc1dd0c2eb3c83ecf2de1b5735aecaa6d5
daa242074b50db33fea96d74b4ffc0f7d6ef3ecbaec1e4432612b220b5dd89ea8dd1
2e7a3ab19a0fad9ca81916b94691af4eeea1b2ede3967424cf693ffb74cb67b7a043
538e51d0bf8d41d7e8365baa0625
ProofRandomScalar = 4dab20fd864de6ceab345e8d755997956ddd1f267a2d8617
5aeae5e1168932285a6f602b4b20a570a697452b3ddbb7d0e29363ad3a6fed19
Output = eb14608be2f14c25b2c9fdd23690d293d0c6aaac501a3405b626b8699cf
34bb9dd4c2d7987b6391519b9480da453611509ba98098b3e79a35acd00f5e9d8abc
e
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 01229ee057507c3e53534ad9db9f6df6ce515d1b8017923b65cada199e93
6a623c8eb3bd08e9b3f6584a85e4ff26e9f869d30b6c1f5bf11b,da4e3069d3ed33e
f13a08c384d74f6dcaed32bb9448c02865efb17a32b82c7f06a9586c63b775932689
cb8215043bf2952776afbc6d9ab26
BlindedElement = 984d89dee8a5cc2b43102ad6bc29da93af93fb516a849497948
4e510eaa1ff8745824013ec56517444e0ce6ca7e5eaa2ecba3f42b29afdc0,d88983
a835d3ca60a07f27ca645fe35fd7d77328d416268e8675866ec92c9fc11731bcc135
b9a77b77c6fa63a9042516f0e8febd5574ac4d
EvaluationElement = e8cf08dc59f2b7a3962ad26038ce35afb82cb856ca7e3ba1
6c47ac251479321a08ac37932c832b12adf4533a02ef3a7016f601dc25ae4384,d82
5c16dbe5c86570f6c5a48297546c1c1f8c6148a8580db27e7589d3ed5aaa299cbdb2
60bb23bc8547f4be62ba63adb2e7f54bc75507e94
Proof = 6565d0e87c344dbc3baa7db461d483efd8100ecc25733dd2f6b7f735c4d4
a0f76388cb35dd5493a2bea09f2830e98fe033f8fb6ddcee4506cca98d54e0b543b0
2655ae0fdb6840af85ca42b3d4f960a598628dc82e4455500c6300d26624dec86e07
bf73dd9e80bae836ceb544cb8a18
ProofRandomScalar = 4e278b9fbe31963bbdda1edc786e5fd0033feac1992c53a6
07d516a46251614940e76a2763b80683e5b789398710bdbc774d9221f74c7102
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
Blind = c3b11cb03005ced988ae863bc6f3e8b59bbd1354548220e81cd0ffb6f9e4
ec2173870ae684f86b1c06e41ecdb9ef83429e58098b238c292d
BlindedElement = f4c83c628c5c1b509ecd78a5651e2ab180ccf02ecdafe73157d
3b388fa945d149d3e56c36aac26f4e5bb914bb1069bf0348905c0e12edc8c
EvaluationElement = a0c254af7cf53d7b1be3c8c3e7cf59fe052064e38b05306b
68ee67a2e6466c2740c4a5bce787652a0c61be6645c7bcf4d81c07063eebc250
Proof = bce79a0516599712cc2c43dc49743ef9325cfce099f4cd2db6669e23720d
062b12bb4cc3b7fddd52dfbfdc3a0fb4bd92bc9943139daae412a661fbd00a00766b
879bfd152e4ad41a3d7ac8e73d0ce79a4087683d97f1f1c83bb8fe4bf2805a0d8105
5dfcf572303bfe8195609d419e28
ProofRandomScalar = 9e414ad5e6073d177a1f0b697d9efa2b60c984df38632f10
96f2bf292478118d78e9edabbe9ad22900ad84b1a2cdcb869c70c832589a471a
Output = 1ffbf9591b674e6a089279a8319c75e949cc277d7b5c757361412180307
90755e90af009768e1b9240c9734d8886c6121123384140b26c38c7a6c4217a1b3d9
4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 87c1563075086f0749e88205237f77416210747f2369383efbec7bf6c78a
77d5062b938e91fbc6ce569a4461a97bda32d0af163d4307bb22
BlindedElement = 4aa02f66af57b0aa3f8d6518d7b1e066626903875fdf672c9f4
ea0ad05d1f785d870b5dc43a0f5963a9c54d717cec1e72c5fb664dc747014
EvaluationElement = c2267138997d553c74c97dbbcaf879930b8ba16053f62543
8907e32ec5a945181063f46d723390de07d90e42332b337ed7d301c0a68e17d2
Proof = 68bf6f699c4078a4b05649431bcd9e60424d4c87b7bec27ff78c0416cd3e
9b965e8025fec6705fb5773fac80800c790cc99ff3a934eaa3099b7fd53f51c7fdd3
2617e51f33d04616df7a28c29077cd4963bd8583b2f38d84f592704231e9f97f46ce
5474fd7248d9de9ed2183c63e20b
ProofRandomScalar = 68481b589434b3b5b6c131de9e080e58e63ca9ce7d0c1bf8
1599e1a6292f2574e3a23e21d5bf79ecc75a16f7a77618bb9a9224c39cf90a18
Output = daeb206a0e1fc120ebe4ad885f851f456f7d8908166839b7dc541f71251
4203d9a3589025b4bfad6a79c6d40bfbf217f44a9aa17874a1ec271b23cced72a44e
f
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
Blind = 41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77e
b20d
BlindedElement = 02441f547a2e792eb2ff79788da348d182c38e2324cf6139b8e
0d0c83b11d2bf13
EvaluationElement = 03f8f8d90588c1567e3ed2f773de5db1d3103a49e8dce36b
7326a290b1937d0c78
Output = 413c5d45657ce515914232ef0bafdbc1bfa5c272d4b403f2cea0ccf7ca1
8f9be
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 7b7f977a1fb71593281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf
539b
BlindedElement = 036787c9803b6be212a4abf23dfb52c6925603e30c4d9e4d17a
fbffd927963d111
EvaluationElement = 03e93f91e53cd96ce53140c0c0df69f6fa9c1efd43678111
06ef10968cb408ba2b
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
Blind = 2c2059c25684e6ccea420f8d0c793f9f51171628f1d28bb7402ca4aea646
5e27
BlindedElement = 02863053a7fc559bb76cd13ba5033c17d8f5be98ee731808a01
3c81d035245adf3
EvaluationElement = 03a7ebff42e330d03861c9a0676e67ba6f90b24981c4cb20
582a4720a46d3c56fe
Proof = 5c4d4251c15e087423475e11f13093c2a26d9d875dad86f7126eb759af80
55bfea38f60d0005ba1a93861c1293e445e5e367d4416eaee6c20d18bc8b45ba050b
ProofRandomScalar = 1b538ff23749be19e92df82df1acd3f606cc9faa9dc7ab25
1997738a3a232f36
Output = a906579bce2c9123e5a105d4bdbcafb513d7d764e4f0937bee95b362527
78424
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 8b45f65717a40c38f671d326e196e8a21bf6cfd40327a95f1ccfc82a9f83
a75e
BlindedElement = 037f62b0fb778b86b90a2cc9e6c980c852dc72f61a8c5b6043c
f948dab8ec81034
EvaluationElement = 028de0c64d82c02804ff086bab06e0a92ee47c89104d18c2
651608ce9294af372c
Proof = dcc13b328c8540839720ac2e0d3499ce02b1b793cfc42b9e507fe908d9d3
30b582f0672c75a8fbd4fd72eea46b23fb539b5dde6e15a03e844fc4340992525385
ProofRandomScalar = 3d35895f4cff282d86b2358d89a82ee6523eff8db014d9b8
b53ad7b0e149b094
Output = d13c62d285a71acb534dcebdf312bfec0e2a3fcb79f4ac32d2dfb0bc9aa
e3cc7
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 83705fcc9a39607288b935b0797ac6b3c4b2e848823ac9ae16b3a3b5816b
e035,644c8539857abe3a2022e9c9fd6a1695bbabe8add48bcd149ff3b840dc8a5d2
5
BlindedElement = 03e64ca57e4b5e591711bb9f67a816a61f5e4da6b01e62da81e
95af145f94e3c0a,03204fafddb8b1d8aa95b3b51e47bf3f7bc6ac87521ab95eefd7
15afdece8395cc
EvaluationElement = 03d62df8971467d70e8e1cd2c2d17173d64ed456fbc0c1fd
574f930b6a0330cd33,03ceed4d321e1f1b812cb2caad35071ffcf727abff1c8c801
9ebb7fd82b0b24cb5
Proof = 70fc8376f56f7c6970eeaddfc4f268291be5c7ddea169496ae9264add96a
8573c1c6ad9306377c44100436c7c5e017ccb1a277a35eb014053702a3943bd1249f
ProofRandomScalar = 316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043ba
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
Blind = 0470f06169bee12cf47965b72a59946ca387966f5d8331eab82117c88bbd
91b9
BlindedElement = 02020e7eb0259b4b4bd8a63dd3071177e2b8dd85608f9cf88c4
a4e7b2d40405089
EvaluationElement = 0322df86453b7d0dd528396d901f2cf49df10c02b5196fb9
95944efeed31b48a74
Proof = 2f8120ada25173ee94ab9499ae3dd5ce7d35c885f2a25f9670cf1c12c9ef
918f52f9738023e2302e697338edc610aa6fff096550dd4b24bec61c8b76be06ebd4
ProofRandomScalar = 466f3c0a05741260040bc9f302a4fea13f1d8f2f6b92a02a
32d5eb06f81de797
Output = 15fce9922a2307349aac2eccc41941283e3c5e938aaf2506f99a6d8b6ee
34ef8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15c1b9ee1e66339439e3925cf8ce21ce8659f22523b6ce778bbd8f8b541b
e4be
BlindedElement = 0268a4e711b93d37611d605f2c0a0ba8baf6627938ebd5235a1
66c0d727226cdd2
EvaluationElement = 02818461a7ba093eef0cba05badde4792653eed89d2f16ee
278524a9d70f7d2d47
Proof = 66d3c5e2467bddce59e4733f1cb7de16a7de4fa7e0b2a125d9b309372a34
c6c8da8d38576dbbe940da0456503a6e2d27a55ce8de0610a0b8be4722f7febac599
ProofRandomScalar = a1545e9aafbba6a90dc0d4094ba4283237211e139f306fc9
04c2d4fe4cc69c0b
Output = a06ed7380210856caaba173bcad06266186c6638d86e372c3c96b9bd2f3
53543
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
Blind = 4dd65065273c5bd886c7f87ff8c5f39f90320718eff747e2482562df55c9
9bf9591cb0eab2a72d044c05ca2cc2ef9b61
BlindedElement = 02f4471ad82815b468ed6f8a565890b7ea08a5bdd5cbf97657e
53d56b89e408d2cea842987b11e21eaa4c3c9edf5363fdf
EvaluationElement = 03d2ea8566ef199d64011b7d0141163d72c1c899848618d2
786acda8aa00c9761adbd764da9d527e3f187885029bea10bd
Output = b2e380ca96ea80f7550a6b663e5f7752d7d7772c46169d72308a8425903
1e804ba577ac34e632f535a9519a692734016
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 55f951785ae22374dfc19eb96faba6382ec845097904db87240b9dd47b1e
487ec625f11a7ba2cc3de74c5078a81806f8
BlindedElement = 028b1f9016b28c0d7ffa72018fa66caf130ad42e260517a756f
32f9d9d5b995a67cdfa366ff8ef9b5cfb03f0ec7e8c303d
EvaluationElement = 03b9523b3ccf732e28abfb0611c21a0db80ea46b9539bede
1824bc33e59e1cfdc5dd0660e603088d182139670d1904072b
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
Blind = 84580de0f95f8e06aa6f6663d48b1a4b998a539380ed73cafefa2709f67b
d38be70f0ffdc309b401029d3c6016057a8f
BlindedElement = 030b29cb373dfede2ff32a048875af7bf27646ab6513e123826
42c5c487f7f75ca228895fadb2cb51a3c5cc490a29876b7
EvaluationElement = 02fc30baa706040fd25536887fd45306b5f4672adacdef8d
2952230b303840e45655c748cf047c344e7a434a45663c7082
Proof = 3f6d130a4cc35e3e41613050050ffd9aaff3ed927b6b4ccfc96bcc2cf561
f58d51ef43b894a6b368b95b47c16cdbab52c5dbbd44a9761a19f6338ff2e673bfb4
e2319e831c4737f056e031065558a2c8345f2d73ca9470e14d640148fdb20c4f
ProofRandomScalar = e17e559ca3ccd1944f9a70536c175f11a827452672b60d4e
9f89eba281046e2839dd2c7a98309b06dfe89ac0cdd6b747
Output = f18884ace2e342f849cea7f2f17de902b9884574fdaa8f507356f482c6b
67013f329e8c899b3c2c154af1defaa11d656
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 7759061965a423d9d3d6e1e1006dc8984ad28a4c93ecfc36fc2171046b3c
4284855cfa2434ed98db9e68a597db2c1473
BlindedElement = 03128b675110ddb78dad990afcc962d8893f16bbbf36a073718
757f4d91e5a0e1a2b6f7a2118c433db44c78ce08dec5e14
EvaluationElement = 02d7ea5cd1cb88a07f1de1a9e0f98945078fc7aff2b35f9a
78e88102837a3b444d6f09540947c31d7eb27c66259f0e7d53
Proof = 14baa204829577b1df0e0be74272ef971be05a57adce39629c26b23b893d
4e71efa6de555784d99d59d203040ec6486ceaef12b23b643dfb48e5f65faeaa5665
0da6d579bf810829081926232d9dcd9ae815ec90fc3baa2b80e881dbc2333d1c
ProofRandomScalar = f96713dfe16f40f2c662a56ed2db95e1e7bf2dea02bd1fa7
6e953a630772f68b53baade9962d164565d8c0e3a1ba1a34
Output = f91d172cdecdea4f8299c8b39426db4c47428b82f8872b8539ad9b019de
b48b8d3c928c572ed988d5591a4442c060438
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 563b3420d7764097502850c445ccd86e2d20d7e4ec77617a423883574303
7876080d2e3e27bc3ce7b5fb6a1107ffedeb,4ecbc087302667fabefa647b1766acc
b7c82a46aa3fc6caecbb9e935f0bfb00ea27eb2359bb3b4ef3d5c65b55a1b8961
BlindedElement = 033bf70953102f1ea680a1bf65974580341a8dbda2e26b52334
26c18f62d16c6bc8033042c98e004a59ae0aa6af7d20a6b,022c42095692ac6e9fe0
2d4bef10763457d5db8db41ae973cf14370e5c460eccec0a2e479b043d21b07fac9a
ac5fc04603
EvaluationElement = 03fc0f78343004ce73ad8ba83e7ad48b73993b32f9244a40
ed4981be4310984b590cf31264df21ab12bf7838d287c35407,024c85d0e51b941f7
2e65c1d5b8c5ca051200d802e7fabc86a1f599f88635ab3fcd113c9da6d8caafd7be
3fc56b0c49ced
Proof = 124bac40edc92f8aabe62247aceb0a501947025354876f51da7500a806b9
27260f8648e1f1740eef022408d77f17903a698a943b598116a875f5e37871f623d0
a41ce2f1a9ff53e819a971974e726bf461bee95b4811c3d0f1ee1d4b4baf10d9
ProofRandomScalar = f77ff0b2ebcfe21e1a1ca4a84361e9f1b18e24c9a40ed5ee
c262bf51dc970d63acb5ab74318e54223c759e9747f59c0e
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
Blind = c405a354e666f086fa0ea4754fb56527be010296ea880e1c6a4dbbc9ede5
43a2ad0f83fd60fdacb59801a9d83b5d1c10
BlindedElement = 0202fd96becd2b9f97f6540c833be9e423d14ed3b43ffef6eaf
4ad029fbabd2403af879641ec3b068711ba2573157cb603
EvaluationElement = 02abf57f3f71cab2026ed849217f1a49cc97168f7e8c4952
0eb18648620d255d69caead39dc4c1ec04d6717fcbddf90648
Proof = 5bf53b72e43cebba15e8ef9dd9de6090588f5945b4d04ff2ff25b5a8bd8f
6621ebc72b1f75b702d9e06165cc921589892845a3d158b8565c04b9f70dff8c189a
53c795a08450c1af0e271e479f16a3a888616d4f6d58859356c68dac0b5848e1
ProofRandomScalar = 5cf7fa02f3ad744eb5baf418275e45ab31ade30669dbae98
fb0879524fb9234e93a8bd048ad9f44b428026396a810329
Output = af52cf184180177970be0770e1c7920aa307b767556a13de38a64723d8d
cc7b344af9b6dd8f117ac2cef249ee3acc8fb
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = fd762bff10c1b9bd5d37afc6f3644f8545b9a09a6d7a3073b3c9b3d78588
213957ea3a5dfd0f1fe3cda63dff3137c95a
BlindedElement = 028f33d8420d4ba8d1bc2316728af6ad2b71c13f729cd0ea703
ba0e3913445deaa5e1d6c1013fca8194eec31dadce7ac1c
EvaluationElement = 03ee3dcad372a7aa0dd9d7aa33177f1b5e90e31d7c04fd9f
8228f82f4308dcffbcbdb88a428d6965895ba93720c939a971
Proof = 4b9e650d35c9fa846b422b73dcbf6ccb476e8f8b8e57bc5851a6fff7cea3
c56bdba17552d11d05a64d832f8a513dcabef8842810f8168d4a035c24ed4fe6f4c4
4997c5f65524d933acbf889b2e3e7defabeb15cc6fb266c8c6197cb9cd164bde
ProofRandomScalar = ddff1365bb9b82b279e775b7220c673c782e351691bea820
6a6b6856c044df390ab5683964fc7aabf9e066cf04a050c5
Output = 8bc546462de3087cddafcf81435d5802c0c31f557c791b115a092d5b71e
a2b6e20986bb624ead85c7a63c976c05dcddd
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
Blind = 01583649f3e9cdf20a7e882066be571714f5db073555bc1bfebe1d50a04f
d6656a439cf465109653bf8e484c01c5f8516f98f3159b3fed13a409f5685928c72d
9dac
BlindedElement = 0300c6f11dfb79a56c9abb778d47884087fdfa2999b172a2c48
ab10c0a06bc16058329701562ce38db0c331635a35d1cc86376c92771f146776e3f3
626398697cddf82
EvaluationElement = 0301d306df92deaa4137b1f1344506112b2fe8215d32d257
df9d05fb763981e99898cf7fe1cf262b186f3bcc2067f0e816a4841652f387f3edc6
19fbf41e655d3f0ac8
Output = 383e3098d74b43f75d2e1136d7e7c08702d992e6f5f24f2bd438f98b86d
9d143ce87281b2daf7d67c94370903ba81495655d6e9626443a895b37bb74c0276f2
a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0017a273530dc66aa53bb9adb4f0ed499871eb81ae8c1af769a56d4fc42a
ef54a703503046d8272eaea47cfa963b696f07af04cbc6545ca16de56540574e2bc9
2535
BlindedElement = 0200d4e8e680135ee19adcf749a2ad8fe61e153e24b7f58ee4a
c5f0b30ea858e38f86ec1744225790296d0066064e18b4ad889eaa582bc1f6c5301c
2ebb1bef4f038f8
EvaluationElement = 02013b06cb9fbade37e8aac7ab94329e3ccb8344c8ba414b
2cc2131cd0de06c443ed800df6a3196f9aaac6e1f1ced289bccfab278f6e27dc152b
09aea469bd9ea85ec4
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
Blind = 013a196708f773cf65852bda777210337d8b3b88754b881aa5fd937ec793
2e725ac43a07cb3ea0e90b40e0501e6bdc3c97510cdd9475ad6d9e630235ff21b634
bc66
BlindedElement = 0301fdda5da4798fe365d606aca1faf0d772fbd39091f47b88b
d87f1c4a53943b358fa5d46df24eaecda8f875409c951a2ea6424ff54ff98b98e7a3
eda31f957710f23
EvaluationElement = 02009e48543890f6c51084a0ecdad159d36ac057542e6a58
65c6505f28209d828d430423a7184eaebcb05edf3185109c8cef76e0be7d416f3699
777028abc613fda02e
Proof = 012abc4044b83283b7498d8e881d3102871cf2b3c0d26d3602fd79a3251c
f42f912a66bf4da0f651babe348c507754cf0817220ab1ea2f22e99054228ab90b2a
0e2900683396864f635836ad14ee5b9a3027d31a9e141c730d28441d7c1bd8e55d54
308f5944f423181e4f09fa729ae39a4589f27e4d560ff8005acff8135f038f8b15d3
ProofRandomScalar = 00eba4687426b0b4f35c14eb2477c52e1ffe177f193a485c
ccf5018abbf875b8e81c5ade0def4fe6fa8dfc15388367a60f23616cd1468dae6018
75f7dd570624d0af
Output = b3e837431aaafdfa8efbf486d70ca2d4364ef86afc7a8941d9bf1a6adb7
bfd8c5302f91ee5796d956b5d3ea95fd0138d55d3059b1f4febf8cfd552e31fa2cf9
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 0085f76f3320fdd24777894218769fc1965033654f34b06b578fe36ef23a
5b9872ade82b9261cc447670debcf78318add682f6055089b0a2484abc37f110b36f
4c2b
BlindedElement = 03004e72d8ee72c14e5963fb807d28ebe0a71e43f07253085f2
ffbbc9ad193767d7868619371fd0d7a8a4e3b6249d0f5cceb52490181d561d41b039
b934707a5d4b629
EvaluationElement = 0201633ac2688c09dbe3db1749dc09f07e86d56305fe092c
c6452d3ee90a9752e1b8345124283ade0df74edd7d11c947030f080db95da8549369
99ddedf4effcac70e3
Proof = 0074e3f91bf2e122523048c0e2143d5b1db1f95cf559b79379c3c9c11f09
50dc9bace3f0b9ceafac0422afd6195a7dbff537f21e075ea5006827051dea182ee1
054d00ae0342e3172f79bba6a985d41289543df7db7099d0a1268e8b5dee1415be57
17d3aca174705d912462e469b89beac1200c0b3a06f8e4759eac5783fcd245202622
ProofRandomScalar = 0165aa02c8e46a9e48f3e2ee00241f9a75f3f7493200a8a6
05644334de4987fb60d9aaec15b54fc65ef1e10520556b43938fbf81d4fbc8c36d78
7161fa4f1e6cf4f9
Output = e8f92bac6c7ae89918d724697d8c45da339f55b61d527c50104e6658280
3a8e6dcceae31b0d499e471aca460194a011d6b8b94fe2886b8b5a0c242079bfbf09
c
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 006915357a04fab501c0f6764e854701129e38071b008286c5fb629de5cf
ea56c0532dd8254a5a6e7fcc9e51e20a1cf4f254335ca57ce603ae7cf03fc00b7a2d
4953,00d60ce57aa6729d935ef02e2dd607cb7efcf4ae3bbac5ec43774e65a9980f6
48a5af772f5e7337fbeefbee276c901e6e57b7ec6752a45c74f3ed36a3eb8ad0dafb
7
BlindedElement = 03019a34eca6981123bf80a5dac91b6073b639b6b695a36995e
2adc186a608e281087f10415ca703cdd9cb78f9113c7607015bd0d2f26d8d67d1d2b
fde442f336845c2,0300bd77def99da2726bc8b69ceb64912b59a044564382776aa4
5389cc237de78e5e498a28a964862da758878eaa917f89fa79a3905b9c6be45985e3
c4d199cf6c5b8e
EvaluationElement = 0200bdcec88e94c95b5dfe4fbcbc63ffaf614bcce8790510
1a0ac574bd2dfc38e04ad52242e399739f8247e6b9092df78c9bb12b249ca65c99ef
f19fa16a0e2949993b,0300761e1ee3572e132bc8e52d5176ef4e135d74151481331
9437b779b71b247c6b95fe12c401c555945529a6ba394107f4b66b5c7cee83143d3d
9908751667274b2b1
Proof = 0018d2360e82d178b1f4c6163ffa3466b3f44f992048e90373fd540f77bc
3942e33a95858892b5acc4efb5cdbee7439e6e341b7760c117188119256ee210882b
a345000c00a1e0e7ac66db3cf8ef3cbff67f7d4b7b20eb0568b6222482b335e70a3c
44d61df136856a686c19a2085d93e4219cc131a74a8a2933783a2793e8a4df6def44
ProofRandomScalar = 00ac8346e02cbdf55c95ef9b1aadda5ef280cfa46891dfa6
64a785675b2c95bbc2412ceae9d69a186038345f8ff704bc925f6818500615a825a9
a6b5646a4e4f11b2
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
Blind = 010204f2476ad5274e2f9d258659e80b0fbd20e4761b22298eba98ae9dc4
fcbc7ad42f5459d29f5c3b170f51d08e65679d984c1e852b2344bbebcb92747c83cd
6b89
BlindedElement = 0300f2fcc5a3948221fcd278a335d6dfc8635a05d87e5f74c11
66505e41f755dc501b846376025d06810fad592b1516cf00dba7e1cc32f5217cc367
f99e0b765f7ee1f
EvaluationElement = 0300500d396769fa1c32a8112563f75221da61343654339b
ec4f0dc463bd51cf529f6abf29160f95462204f45a7b8336c883ad20b10459cae238
2d6e41407a10056ca7
Proof = 00c4ee78304b60083768753b47ddb0c68b060346c096d5053bfd4374df1a
e9aa8b34a9e021a0e6565bb43044390db33764ece8009ae70d0599de29bb663d0f8b
9a3b01d6296f5b6bffe5f686cbd37466a25b0efd9e4943b108536e024019aa9d9d6d
b5b5d1aa085090ba1d7ea4bc33cf200baf681258f1ac2482933746a2a858415b6603
ProofRandomScalar = 008492e4dc9cd7f7aebfb1d3d2b8c7fa7904503aef20c694
a01d3e1154fe98e7232be9eaec5789a012a559367b1f99654ddef5acc7b0dbee75bc
d8bb50363ec64004
Output = 70ad5e29de9f6e35f16afab3b97c1b26fdf6be0da60aff48a99980ddb8d
7c2d728a8a5d2837179bfddd612712e014c0c9b9596cbb5a6ee6761c564dbb8921b4
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01ab3a90cc9da17604b2e59a93759eb0985d2259c20e3783be009527adf4
7f8fb5b1437cba7731c34ac70bc6ab1b8c14ff4110afc54c9598d5f1544830f9d667
b684
BlindedElement = 0201900b35b9009c79e6ce516b4206fc8430555ee26d9bdba16
865e19418a06aa899adb3dcb5226535feab336234bc8f40e3e29a80b67e6f55d1133
a9362c5944ff882
EvaluationElement = 0301cfbc891616e82afb285e347ed28f27ea5071f9c9a887
11b776b2d3111d991d69dc13b3c0a4ce3b58c36c2f603893b677c79eaefae013ff70
66b4f103f8c9191991
Proof = 013255218e01044d4f44236e34ba80415e37e99e8cb5893052c9470d6fb3
371887ee46cf5c487b5fe509774d7b3d766c49a3ad5ba1dd75a47b9362b8a24bae1d
c92a0131c78fc528ee23f32a644d4da74dfdba866003d5f4dba2a0f963ddca588661
a916441d4c4e2548a041566dc18650c0b1aaa8ffa04eab55f37bc4d4d9adf5fd61bb
ProofRandomScalar = 008c15ac9ea0f8380dcce04b4c70b85f82bd8d1806c3f85d
aa0e690689a7ed6faa65712283a076c4eaee988dcf39d6775f3feee6a4376b45efbc
57c5f087181c9f04
Output = ee2d8e42030da6283ab59a11f41a171c65e208306e00c6f965a56c10f33
bf0942bb38b7e1a33c70bc3542d27220379cbcef8b91898c720be948e9db214a14bb
9
~~~
