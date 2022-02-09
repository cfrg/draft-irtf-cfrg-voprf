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
{{!I-D.ietf-privacypass-protocol}}. Verifiable POPRFs have also been used for
password-protected secret sharing schemes such as that of {{JKK14}}.

This document specifies OPRF, VOPRF, and POPRF protocols built upon
prime-order groups. The document describes each protocol variant,
along with application considerations, and their security properties.

## Change log

[draft-10](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-10):

- Update application interface considerations.
- Fix test vector issue.
- Apply various editorial changes.

[draft-09](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-09):

- Split syntax for OPRF, VOPRF, and POPRF functionalities.
- Make Blind function fallible for invalid private and public inputs.
- Specify key generation.
- Remove serialization steps from core protocol functions.
- Refactor protocol presentation for clarity.
- Simplify security considerations.
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
- I2OSP and OS2IP: Convert a byte array to and from a non-negative
  integer as described in {{!RFC8017}}. Note that these functions
  operate on byte arrays in big-endian byte order.

All algorithms and procedures described in this document are laid out
in a Python-like pseudocode. The data types `PrivateInput` and `PublicInput`
are opaque byte strings of arbitrary length no larger than 2^13 octets.

String values such as "Finalize" are ASCII string literals.

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

## Prime-Order Group {#pog}

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
    Client                                                Server(skS)
  -------------------------------------------------------------------
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
  return "VOPRF10-" || I2OSP(mode, 1) || I2OSP(suiteID, 2)
~~~

[[RFC editor: please change "VOPRF10" to "RFCXXXX", where XXXX is the final number, here and elsewhere before publication.]]

## Key Generation and Context Setup {#offline}

In the offline setup phase, both the client and server create a context used
for executing the online phase of the protocol after agreeing on a mode and
ciphersuite value suiteID. The server key pair (`skS`, `pkS`) is generated
using the following function, which accepts a randomly generated seed of length
`Ns` and optional public info string. The constant `Ns` corresponds to the size
of a serialized Scalar and is defined in {{pog}}.

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
and `Evaluate` can fail if any element received from the peer fails deserialization.
The explicit errors generated throughout this specification, along with the
conditions that lead to each error, are as follows:

- `VerifyError`: Verifiable OPRF proof verification failed; {{voprf}} and {{poprf}}.
- `DeserializeError`: Group Element or Scalar deserialization failure; {{pog}} and {{online}}.

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
skSm = e617ae6f2d10de61e16cab73023c5a2df74335d13f89470957214664468d2
e0b
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = b617363ffc96d9dd2309d3f8bd7345b5226eb9c863912cd86b8
f34cf754c1b4e
EvaluationElement = 2a70a5853df41864476277e890def81516e0eebe6fd8dfa1
c0b272be5742e365
Output = 8a19c9b8f4459d541ebbfff4e29f36620e44e825a27b0f2e3a3c0d8e963
588ee04348312dc8b43a48c41d4e7d904f95c91813a6b4f624392433f0568409da62
8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 927e71dbbceecf21cd0631fcb7f15ca0143b9a15e587f84a35b
8bd20bf2e0767
EvaluationElement = 72e8baa4a2029654724b1a6d478d67dbf14551a156a8abac
08c321b3df878f41
Output = bcdbd421c0863495d63d81a868858f34f5215437c5777072a92703f36b3
6c4a2d3e7e54a5762e70b06223527c211e2d4364481270f72971a2db8b7ab8fad84e
e
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = a3b8dea4a99be2469da7f7d2d93fe5f2867317d6705350475d47739c7214d
a07
pkSm = c00fbee6832a8e5d6cc1d1a23315daf6a6018f19e29ba37b05499259da854
b48
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = e48c153560339cb803b87b878b34409e4bd31de9ccc5c234948
6c4e7ef77da25
EvaluationElement = 74e674aa9e58abaf6a6251ccf6abe8a2a48ba6a97b92fc62
58931195e136b45f
Proof = 617d0d3613218c9dc965f4fc193ba610f9051ea78a6f929ea5e61e0e56ba
f501841cfe6244bcd6d1226f084427fb64299c74b5744edc551a13206e5bd52a5a02
ProofRandomScalar = 019cbd1d7420292528f8cdd62f339fdabb602f04a95dac9d
bcec831b8c681a09
Output = 4d5dd83db5bfd850e3e0c17519f1013aab904e7b131dc1ded31f7a76aac
f040f6b344b0e635cf6df30771a35157e0e3d9539f7a891b48cd8521692b15c51538
d
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = 0a52c861e226b47ada988a29edc104e051b54f6032f2d866e23
ee6b0c220f42a
EvaluationElement = ca56a4e2b32d4af89efcdef66aeae8b8551ca0a73b82a64b
a18ead5bf5861321
Proof = 1555322ba9b9c7b4ab068903d2d60f2978d610c9bc3ff0116ddc2be0cc8f
4504741797da5132e06e927de2ec24e878623bccf3b8f8f97879b2dd5ac1a637190e
ProofRandomScalar = 74ae06fd50d5f26c2519bd7b184f45dd3ef2cb50197d42df
9d013f7d6c312a0b
Output = 5c3fe06ef39905710a124df0727c6c938f48234b35ccc4548c0736d7f6f
36e6b7333a9aefc93d6b1ee20151a40bce453866b62cf5d41799982fee6100680915
9
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0
d50f,533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0
c
BlindedElement = 801289b2c2bf4aa4c3c471c9e25063ce8855fcd761c51d31557
e6ec94b76a17a,94f81def5c1e7a77c350a996feb4633ddea2764646bb81a85e3fb7
4b11bc5808
EvaluationElement = b6b60efe443b88118c6a32008ade0679224299cf8e76cdac
9c4042380f0ea361,dee53f55c30809e2ea0f8865c04e7ce334054582942b43da550
759bbc3694f5e
Proof = a825d65be8c057f78c0abf98d7927af2ecf006a03195125a0ebd3adec113
d501a66326f5395aa12691afbaa88eb6e93e97e3b941da14a3ed19b37183774ca60c
ProofRandomScalar = 3af5aec325791592eee4a8860522f8444c8e71ac33af5186
a9706137886dce08
Output = 4d5dd83db5bfd850e3e0c17519f1013aab904e7b131dc1ded31f7a76aac
f040f6b344b0e635cf6df30771a35157e0e3d9539f7a891b48cd8521692b15c51538
d,5c3fe06ef39905710a124df0727c6c938f48234b35ccc4548c0736d7f6f36e6b73
33a9aefc93d6b1ee20151a40bce453866b62cf5d41799982fee61006809159
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 024eaeb72e5b3729d7f19d90aa44e3d2f4c445fb29011ffd755655636f2b1
00a
pkSm = e001954ccd18ec5aa89bcbf26c03d84dc4d9c9b973d9f06b1e0ceb7b79f41
d65
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 7e5bcbf82a46109ee0d24e9bcab41fc830a6ce8b82fc1e9213a043b743b9
5800
BlindedElement = 2683b3e2de3b541432f2ad1740a127985b32b2b35f24c26eabc
444aa7590bb20
EvaluationElement = 4c1145bcc3104e002fba743304fe4f4e65bd0de1df62fd75
f77c4d1c24aaf937
Proof = c006cfb6add7864013a12ce5676cb22b6ef657c7ebcfdace0931402af59a
e802f271ca47a022934263d33cf29facea40aeda42c893eeb806179f8398e867a70b
ProofRandomScalar = 080d0a4d352de92672ab709b1ae1888cb48dfabc2d6ca5b9
14b335512fe70508
Output = e7ed59e3f808c369598961ebfd9af74272894e0904d1c11653a21b08204
dba1a5fb5c3dd6be6c419190a84b576d91eb3d8d920d450fee0427fd24524950d72d
6
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = de2e98f422bf7b99be19f7da7cac62f1599d35a225ec6340149a0aaff310
2003
BlindedElement = c68819c49527d6b554e61003c68982edd5b0ca807c5db4cb9a3
d4267dbed2445
EvaluationElement = 984f16aa96c10da65cfdcd33f1f7c1bee01fa48e097c29c0
4ff248a1a3352677
Proof = b19b75135b72c0e69a298c433ae591b0785878f464e40063550f109d6a04
630effa7eaba98f40f99717245fc0e530abae0877275a237133d4c50ac1eab89c206
ProofRandomScalar = c4d002aa4cfcf281657cf36fe562bc60d9133e0e72a74432
f685b2b6a4b42a0c
Output = 9a0d8c55e2fef4bada9fb5877a0e739496e539a0d835722911dab9ec112
397e763a605acbc072619e8b8acefb8ee704a357556edc802648089d684baa763ce1
4
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = e79a642b20f4c9118febffaf6b6a31471fe7794aa77ced123f07e56cb8cf
7c01,0bb106c0e1aac79e92dd2d051e90efe4e2e093bc1e82b80e8cce6afa4f51980
2
BlindedElement = d25127980200015eb72619c0126f1617973f0a35f69c6b88355
d214a7be0fd73,6802ef46f3ccf06fd5e14f3f8b8935451427ada3aa5cb5d9126d59
8fe1dae34a
EvaluationElement = f2c4354d7bf6612fc3d89a208d5fc0d89ccf17ef95392f59
45d90c1f6e5ae06b,48217865c16aac3f3ee1a3f76c886a19f223cb4097d990d0f12
58c37b9adf12f
Proof = cfc1e5b3f79fc1411400020eae21bd14f2767a39e341793b06cdc01781bf
ea046734bf7cb2aef9bc42b1d1af1f5ec09eb7af31c476d5f2c552aeda1535b93c00
ProofRandomScalar = 668b3aab5207735beb86c5379228da260159dc24f7c5c248
3a81aff8fbffcc0d
Output = e7ed59e3f808c369598961ebfd9af74272894e0904d1c11653a21b08204
dba1a5fb5c3dd6be6c419190a84b576d91eb3d8d920d450fee0427fd24524950d72d
6,9a0d8c55e2fef4bada9fb5877a0e739496e539a0d835722911dab9ec112397e763
a605acbc072619e8b8acefb8ee704a357556edc802648089d684baa763ce14
~~~

## OPRF(decaf448, SHAKE-256)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 30f71e5b5be9c91dd54c5a48e82be8d47eeb2cb2c45d7874a45dddc85af8d
3f95b1ce73a99c47edc26ac9ddd936bd9b6b73728995bf1d213
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = d62851d4bc07947c858dc735e9e22aaf0576f161ab555182908dbd7947b1
c988956fa73b17b373b72fd4e3c0264a26aa4cab20fd6193b933
BlindedElement = 1ed29aa7f25b5d67132f76a1059c6717167974773998e240bb9
deb7c7e3ba3597649fa636d2f07fbaf017e4c9d783db8a6a4fcef3b74f2b6
EvaluationElement = c260604a5cf1e831a134ddce3c47f7a703e65c5cb4ff58df
b3c8139432c852d421e30c3f5b7dafd4c84aef26c29cf95e47d4d28b0788a342
Output = 1c1a9df7d0616e0f5fdfb6479acec73a4f5562da8f9488f3b6112ef11c6
7c5900e0abc3a169486ac7230a306c8796562a045c66305ed7cb2a3fae658e45eae4
c
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = ac345e8d755997956ddd1f267a2d86175aeae5e1168932285a6f602b4b20
a570a697452b3ddbb7d0e29363adebbcb5673294396b82931f37
BlindedElement = 20bdaf566ba955c32230099307ad70250631ec956fb8b96c91e
693b75ad3357757cbd6703f9c4948f8568bc6ec3532f7113c119dd68bab78
EvaluationElement = b0b112f04b454e45c9652f6f0d40e55ec1b5edff240feb23
49524dbdb05b3fba8959565c168271b362c140f2b868ec516f9b55ce7bf54cec
Output = 95f519e8ff2b54d8d596da2c54829ae3dd900f5c18eef48efa03ef6694c
505bea17b7982246c862d081b9fdcf295debc60abec8b0ddbfdf48bd302a3fe61b21
e
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 44c46e78aa6386cee57a46c75d124b13ced3e5f055caa3baaad61501330a4
24463400453c97245a8f7b4c65f2c4c3dabd09a049c034f9e20
pkSm = 78f4233110896fd41531fce182094c3bc4cf65f97b23078476b3b68118736
617172d3735c5832081864e7c75cd3ddb449e93068b34ba863e
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 4bdfc97a75132d92a1da241baff84fada3e7b12d5b712efcac9ba734d54c
2b24bff0ef6310404b5c05d60d7c258cea6500229ee015149f0f
BlindedElement = e419f756b42bda5662dff0248f512fc348092fb853f08ecd8c8
af1c6a9c7ee94134e6605777dc8f4e52381eaff23f940c242c20fb037b7a1
EvaluationElement = 50a63c74569992c13020fb2f831e5f870935cdcf3bca3635
eef0d3fa13861aa3c60fe8dbebeadbdeb06d2d9fbd2dd068040eebe10c2978db
Proof = f00d2a00feb07c37f96824b67cf334d417ab6488e23accc06799f0677ecb
dc2e92e5a49df3b669f2c82a1d5d3cf7ab8cc37f9a4dc4f5873767b67522d3ecaa3b
bb17eda3af138b8203940194b14b731582a385ed3901042a44edc66cfe5c3f6934df
247b57a2f85cdc4b5f69a9693a1b
ProofRandomScalar = 54534ad9db9f6df6ce515d1b8017923b65cada199e936a62
3c8eb3bd08e9b3f6584a85e4ff26e9f869d30b6c7c6cc56fd94e306974fbcc3b
Output = 3db64b6f803391e7c9803135457da250eb29778480c30f29d53e9ff46c3
ce5ba9555418fc28af347c18b77a990eb904d0043a3411837b6d316f749428a9a370
4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = beda1edc786e5fd0033feac1992c53a607d516a46251614940e76a2763b8
0683e5b789398710bdbc774d9221dd33c509b4805fc26f0c8d0b
BlindedElement = 34cacc23008d0efddc88bae8050c25f8e69229414bd73cee24c
cc524f3f65db427450236ad5764eefdb0e831c0faea99334e975f79542521
EvaluationElement = 8e62bdaecd9611710281b793cacac716a8a4523fee81684a
b42b7d7bdff0d110a661c82875c31aa4b9832501b110c3d9cb0fc77893abdc2f
Proof = bec0731e0281675c8fe09ebbf7264eae2b3a2af42bde263f91d12feebeb5
402e2fbe9ca331ce740880cebd77008d90746278bb71ddb7ce095eabdef62f3963bc
01ad6aedd3f3e32d31804558f7ae1c46f653f984e9df158b513c42d2ef2bf9ce6052
9d0b47add4bb58649b7e3296f82f
ProofRandomScalar = 00cc800042a0cff31f865698f8858efa75a1f0faef934317
dd6a10bfbbb39f9f2d97dcd5ff4eae02980b08fc68da7b71d39399dc4eb0400a
Output = 4dc9ec52b6aa7f1f38a320d10cb58e0d86b040f6376d2f178f42c99986f
e932aca7162cb72dd94056724617979c0f7ea652b1492bbad1d82748a38ff4daf129
8
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 89ae863bc6f3e8b59bbd1354548220e81cd0ffb6f9e4ec2173870ae684f8
6b1c06e41ecdb9ef83429e58098b8f30a6b49d414ad5f941cf05,7b1f0b697d9efa2
b60c984df38632f1096f2bf292478118d78e9edabbe9ad22900ad84b1a2cdcb869c7
0c83260691e69ea7f473c3b478707
BlindedElement = 2a67bead487e7302d54869c4a74f9caa271a9aedeee4bf9a846
d87f686ec9b6fd598a8d5f5ca09d3284c4d1243bfc4b0bbe76b70e2880301,520ca0
e0f0a5e226a807ac1c9b065a2a0ea9743927c1044fbf3f7dfc0ee02b22346f60f828
ea37af5b453b22f50d8938379126df2d7aab9f
EvaluationElement = 3ce2fbd38b18c71d6d2fa49c10c53920ff881bd7d847cc76
09adb6cb53f343c686c7f4150d749ade118d092cd3764aec2485d4839da6d945,aaa
639b0d895107ada08909c3b85bf5765b1977fa5b5973165e947242b01bacd8c676c7
f19a711f615193b7ca3d61ebed61e4edad76f2873
Proof = d87cd686dc22c0b831bb4481c6e8f15d1de03f386155cb9204e1ff77f8bb
72de613fa56bb64806e06290c847a2f3e6adcdac81d4a63eaa214f7751d8671901b0
388442499663cbec1825c1e6f1ab8965cda1f4561e3cbe0a841aed821e4241eb742f
baedd13cb6377655619d6384540d
ProofRandomScalar = 7baaffc0af7cf69078ce1702514d93f32828684a1796b559
988623c12413cf511d13cb07ecb6d54be4962fe28eed7d4386c156301dc2db01
Output = 3db64b6f803391e7c9803135457da250eb29778480c30f29d53e9ff46c3
ce5ba9555418fc28af347c18b77a990eb904d0043a3411837b6d316f749428a9a370
4,4dc9ec52b6aa7f1f38a320d10cb58e0d86b040f6376d2f178f42c99986fe932aca
7162cb72dd94056724617979c0f7ea652b1492bbad1d82748a38ff4daf1298
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = fdd59cb218c7fbdcd48b18ef21ab647a6c210110c765bc3da6c11e563671a
48402c23129ce2ffd021d99da5a2d04158883c65d7f74a4901b
pkSm = 1223e0aec4ee5bc19181078be380cc745d1896e1369aed3cc8a45b40ba3f9
aa1f79e23d542d6529e17465d1954d75e336910c6417de99200
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = ee671e4c9b6783bd5e4a55d2e8474fe0ec811b4cca7c0e51a886c4343d83
c4e5228b87399f1dbf033ee131fe52bae62a0cb27eb7abfcab24
BlindedElement = a271c346e4d2b9d303246f7517e47db33db1a9ae4b611bda0e0
61993d46236b2dcc0766dcff220facc87f819ec3b4da4cc81b4a90401ad10
EvaluationElement = d25804cd87f932f0af5ac1d5a11f4296ceaeb3ea2454fa27
f7b294c06798cb0d8612afa4aeaa2d06bb23f647db1b7aea43a2e002b875d20f
Proof = afb580960a1e8b215d083b9c015415a2e8f792ee31a163cd4fbc73fd48d2
ffd4efd49c3ec9c00d2136fa94810e255dc404dc17e57be2f43bb2747f56777af435
3ddf8eb48b3f5247aaea27a2ee3914c5664c1c6489327ccdae6115a417d2de6a2c88
60bed004f25d648470b35cc23e25
ProofRandomScalar = c4b297c662a87631531aade91c0558d87224d92247bdfa41
9a53af4cbdb352b0a2016e5e5f6c0bee4a642526ef9910289315b71fdee5df1e
Output = 2a08f81bf204eb43a57dbc011946861ed715a2fd3d39a3b35e43c74d07d
4734149ba163389a02f6cd33fbb5b84e167d35dca7a7dc00b89418398c255c8293ac
6
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 1abe4937f28f531b14ac96b844320e7a66810c2d9391cbb877348301ab59
a3a91b4a2129672886ae5da7839f2ac8cf1c5fa92703f5b3fd06
BlindedElement = c2a99f5ba8fc44e134c8db3be1d7e099e12f2c32e6693b0a7eb
2feba6a714bb95f425539d4b3419eae870c18e844aaa1b1779e81095c9991
EvaluationElement = 365ea3d557561d6f63db90fa8671ad6862b9cdcff86cc0c9
3390595f260f625ffc65ff1ada94ccd2b9832e7057ede80c16e55af0531511b1
Proof = 715c9537f285911fa89455f1348d2628fe3db110af35b0e3951934eb3926
f0cb89426b096e87c5bdf3ff98a5e968dca273a58599a4668d0a7c107f3d6d5cb63a
e667caa7a76b768c6cc29934ef36bca83a931cc64131992eac6cdcac48f565b8db7d
7195de0315e07f92f492ce0d4215
ProofRandomScalar = a3e896e126d371f6380ca41757f6458b93b049e1b0d73ab5
b8d914b08dff3e52e62ea8898d35b2862d28ff4c5f89353d25d6b5a8dc014d3b
Output = 80ac73a09fbf8cbd329ff1b7f42d8d14e46ae5b732f776f3203f0680daf
265254360da0afcd9dc1d0cd3858ab21ce8e7a19f0426d7e701cfda34fb8238c9e43
4
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 255d8adc40b8f39f14cd8bd4ade8abbb95166afdc9e922203abe7a853985
4c64b943b0b46e1e1b47cfb52e9a0867c8cde22bcbdd724d9f09,71bd897c56c86b3
1b096103b7e2d26d0f4d66be95299379b41668dbbc5ece26cc212d9f2cbfaf479efa
17b7f6b056dfcfbee5bd7365cea26
BlindedElement = 72b57bebcb288612ea8d72639b475b9e0a4f6b3ff2308cee0aa
a6fd23a8fe823696ee3cff5dc598a83af563b235de901a351b55e287539b4,7a3910
81e4d98562bb0a68f7ef66bc6b351d9f8a23a22c516e65c26521cf8564dfe3326f58
40c94d89d527ae4615dec249812c3c218183f5
EvaluationElement = ea315ada10a2387d809d569c540b87392147349920930f24
5b9501b330a6b5e028a7b8a90329df991ff2e651221cb230beee341151af7b71,782
acee03c31f481f8c5aeee531100acc2ab257299c7e8b5ccb6bc9c8eee0b85c52fd86
c64da11d9a165f40f2e1e6509147eeb7b9a96d0fd
Proof = 93cefbf2ce0770199f131a9e68faece752fc67fc9c3330f40ba735c897ce
101cbce45d2cf7a1831a47697ce773ef662fe8c037adcefa463f8fbc027790bc9a0a
1aa5904f86b57228883923fc1cd8b5fe91b9f3480e17c5cd01c12848f1e7408300c2
5a6750b3f35a91cacb67e98da02a
ProofRandomScalar = bbbf1ebe98b192e93cedceb9c0164e95b891bd8bc81721b8
ea31835d6f9687a36c94592ab76579f42ce1be6961f0700496e71df8c17ab50c
Output = 2a08f81bf204eb43a57dbc011946861ed715a2fd3d39a3b35e43c74d07d
4734149ba163389a02f6cd33fbb5b84e167d35dca7a7dc00b89418398c255c8293ac
6,80ac73a09fbf8cbd329ff1b7f42d8d14e46ae5b732f776f3203f0680daf2652543
60da0afcd9dc1d0cd3858ab21ce8e7a19f0426d7e701cfda34fb8238c9e434
~~~

## OPRF(P-256, SHA-256)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 274d7747cf2e26352ecea6bd768c426087da3dfcd466b6841b441ada8412f
b33
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = f70cf205f782fa11a0d61b2f5a8a2a1143368327f3077c68a1545e9aafbb
a6aa
BlindedElement = 038e72bc4eee15e38bb7b34f2f742abd7c416365c9d48d9e086
14fdfe021d02554
EvaluationElement = 02096589dc7255d85e719fc261e062112d350cd2a1c51f94
686927c6ff8a7e018c
Output = 488d693c0d43ab75703901fa1398907cf7dc7a90978d1c2f0def63c88e8
1b8b0
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 482562df55c99bf9591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6
d689
BlindedElement = 0348e9171a338d31bd5d62091cebaca6fdd770543cac29b1193
3bb2790607adac8
EvaluationElement = 02a70629dd83977220b1ad5a1bc2eb59b9d7bad8bf08cf3a
1f897f444a45bc098e
Output = dacd8400f6fae62beabead9bc27869b5109fb5d87da338ae2488712ec25
f1be9
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = b3d12edba73e40401fdc27c0094a56337feb3646d1633345af7e7142a6b15
59d
pkSm = 03f9fc787c9a4dda44a4b811a961d1fd60f87be7465b8a1b9058dc534dae7
0624c
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = e74c5078a81806f74dd65065273c5bd886c7f87ff8c5f39f90320718eff7
47e3
BlindedElement = 02dd74941094e91fbeedfcf29a245332e0cc992ab748bc634e2
a49aac3e029b5ba
EvaluationElement = 0235e760daaf66a00d98d50ecf8b9a95f4ca312bd794a524
31050fc196ada2099c
Proof = bc8844fa2cb143aa254f849315d9dff05004a69364007b06bf2758dc9cad
273fcdefc3888e11e6ef3777889134ff7cb74daccda0332cfe95bc589e298e383beb
ProofRandomScalar = dfc19eb96faba6382ec845097904db87240b9dd47b1e487e
c625f11a7ba2cc3e
Output = 9df5d51a9149a86c3660396feabaf790b8c838fc96012adba5acbd913f2
a4016
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = dfe89ac0cdd6b74684580de0f95f8e06aa6f6663d48b1a4b998a539380ed
73cb
BlindedElement = 02db5c16d407fd39ad04a9a8ebfcc9198b428ef80edea0cf984
9d5eeb56d333475
EvaluationElement = 03dca508a13f0bc915209163772aaea259cc817e2092fbad
9d9df95ef2d411aea0
Proof = f891ba5a37d5b128c33792a0b8712977efaee16c83e664c416f771a2c2ca
8de30a99330150a17f26f5f6abd34daf0bb64131363a622f1ab67d3d853b733c78ca
ProofRandomScalar = 4f9a70536c175f11a827452672b60d4e9f89eba281046e28
39dd2c7a98309b07
Output = beef8ec835625f610d616d32b1d13f2f899f07c0b8089fa48a1f0ecbc5a
91b8b
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 9e68a597db2c14728fade716a6a82d600444b26de335ba38cf092d80c7cf
2cb6,d3d6e1e1006dc8984ad28a4c93ecfc36fc2171046b3c4284855cfa2434ed98d
c
BlindedElement = 0353aea5ae6c806cf77a2a82e6b3b99b7165c9163459be4d3d2
170a1d72833cb6b,024b34dd817212f20928da9d049f5ce4895230f8552eb3e405d9
31deb617ddd6bf
EvaluationElement = 025a6ea5558bc219bb0bf94f01c16550fe7c6d45e08f4622
a571ac8eb5403f5c12,0300c22a96ec4357465f51e20bf88401ad013e3e6aa9ddf35
6088d6550e22a6943
Proof = 409b25af2adf3cd3d8e367ab6f239a7d63159a9463ac8b75120f5a177ec3
c8a20f68bac5f7dc823441ef82697883e71e7446b8b134f2a2afc4ad1395d014311d
ProofRandomScalar = 6e953a630772f68b53baade9962d164565d8c0e3a1ba1a33
7759061965a423da
Output = 9df5d51a9149a86c3660396feabaf790b8c838fc96012adba5acbd913f2
a4016,beef8ec835625f610d616d32b1d13f2f899f07c0b8089fa48a1f0ecbc5a91b
8b
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 59519f6c7da344f340ad35ad895a5b97437673cc3ac8b964b823cdb52c932
f86
pkSm = 0335065d006a3db4fb09154024dff38c3188a1027e19ce6932e6824c12764
47766
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 4238835743037876080d2e3e27bc3ce7b5fb6a1107ffedeaedb371767432
b68c
BlindedElement = 02056203366d4e0b163fc71c7fe79e768a1695de901f20dd034
5db105e2f252c85
EvaluationElement = 02952ec41340b9b8af78311e1e4e32336b7f051f26fcb25f
a8c107f114ef30cd29
Proof = a69d58731b50e3e7c36967564a547e06d250ffca3b7514059293e8e66d24
765d08cb0ca2acd6e69095fc3ed667ad18dee66b233de708e80eab8b41b388d42568
ProofRandomScalar = 3d5c65b55a1b8960563b3420d7764097502850c445ccd86e
2d20d7e4ec77617b
Output = af6525716fe5dd844076bb5cb118ceda08c02c2d1a02368922ddad63f40
f8b44
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = c262bf51dc970d63acb5ab74318e54223c759e9747f59c0d4ecbc0873026
67fb
BlindedElement = 0201b75766ff1131bce84876c6e48bb2563a2379f557d49b9ce
64d8ab2590a7bef
EvaluationElement = 023f36e0137143e1aeadf81c0bc052c9987e9b78696160cc
e5d2f64054858f4560
Proof = 599c9db8053deefce43a73867fc433be646f28f7ef4590d88b2a8b2483f6
bcfcf40af80ac8a6c9bdffd714707974321daae734529efe51c83608b411a807b9f6
ProofRandomScalar = 6c6990f0fcd9a655f77ff0b2ebcfe21e1a1ca4a84361e9f1
b18e24c9a40ed5ef
Output = 192f4e5d4f89ffe4b9cea5c1c9619ffe32443a5c04fc35f98c3821420cf
1890c
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 3f95c9b1334d8af16ae1e69f5adc24e5aa89ebb63637c835fd39b17a1a44
53ec,9801a9d83b5d1c0fc0812c10e18f146b14d7eb94755a918bac1ef8d69d21a7c
2
BlindedElement = 021a32a91863ca915d6b06aa46d3475b8ed1986d8829da7908b
dfcdd99c01d86e2,0399bbd257e2e3f5b635b387eb9cd2ec111bc5d3765b72fb659e
838772516fa43c
EvaluationElement = 02faa727cf8fc107598ac62ef9902712f049051978da2f82
dc71161b9e00db3093,02bd237d130789aee8a711d5fad4b6428518c9232215e8ffe
5f44a8cb6f02f28ce
Proof = 04ce2c29a2f9905dd44c53aed9201fe38a3a8fcad580c0e0557c589753dc
52e16ea59e60dbfcfc36c0d56c6e47f7da3098a68c16666d078516387dae74ba616a
ProofRandomScalar = fa0ea4754fb56527be010296ea880e1c6a4dbbc9ede543a2
ad0f83fd60fdacb6
Output = af6525716fe5dd844076bb5cb118ceda08c02c2d1a02368922ddad63f40
f8b44,192f4e5d4f89ffe4b9cea5c1c9619ffe32443a5c04fc35f98c3821420cf189
0c
~~~

## OPRF(P-384, SHA-384)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = c0503759ddd1e31d8c7eae9304c9b1c16f83d1f6d962e3e7b789cd85fd581
800e96c5c4256131aafcff9a76919abbd55
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = cda63dff3137c959747ec1d27852fce42d79fc710159f349e7da18455479
e27473269d2926fec54d4567adabd7951ad6
BlindedElement = 0329dc6d4edccedd6f5d94c91dcec4cfb93349258cda85d0754
1f4ad86463d012b09717823b23b086f70399921ac4b4c0b
EvaluationElement = 02b11c1fc222a72dc4114859c6006e34601a07c3c33362eb
72137ea922f1348f80df759bab1af1034c06a3b4b2baca0b71
Output = b7ccad41ed7f56be97621bbba8cc3a4f5e8a46a28d72b0fe089d12802f8
6f080b20726e01a99390aba3437ac50c640d6
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = f9e066cf04a050c4fd762bff10c1b9bd5d37afc6f3644f8545b9a09a6d7a
3073b3c9b3d78588213957ea3a5dfd0f1fe4
BlindedElement = 036ea3309fe97f136a609a1fe2304071092e3a581ce92880c48
61f67a1419b7ad6345f9c9ec05540bebdeef65abcf53c8b
EvaluationElement = 026144842660ef29aec933c2bf3943be999ad2d05700dce7
7bdae7a7bed76e2304b6a094ee6a03d81b8ddf16ba4395a586
Output = ca7dc32dc6434101f35a790717dd591e5963acc86d20fda68011fe228fb
76be8da7f42c6a92284df88fb8e69480a3cb9
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 514fb6fe2e66af1383840759d56f71730331280f062930ee2a2f7ea42f935
acf94087355699d788abfdf09d19a5c85ac
pkSm = 02f773b99e65ad26e8cd20614910ce7ad74c1baa5bdbfd9f124389dc8ef44
b5989f5bf036f6802dc2242fd7068b73da29f
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 61247a74d0c62c98ddff1365bb9b82b279e775b7220c673c782e351691be
a8206a6b6856c044df390ab5683964fc7aac
BlindedElement = 02c7809df9e1e0a24d66587636e8078477515dcbfd19c0fc6b1
a1f081a9549f686f5953f65680cfa94c8f30f2086a69a07
EvaluationElement = 03e56298c85877ddaa4aa9dc64ea1f586ed2c7491eea6ca5
7a5369c01f40f8343f9a1e6740df883b08d3ef266a52f187a5
Proof = 7f6ee5244e031e7b6355f9e7cbcd1057df4b254f2e8b81b0f7bc99bf7faa
36b4cd3d98d5e3e434e5235145642a40ab15c5b92c5b53965de6c41402a21535ceab
e6aa2cb58553b3c3a5334934fb8b26b8126e979fa110112ac2e3b3855debb2f1
ProofRandomScalar = f5685928c72d9dab8ddfe45de734ce0d4ff5823d2e40c4fc
f880e9a8272b46eea593b1095e7d38ba6ff37c42b3c48598
Output = 7eb3cc88d920431c3a5ea3fb6e36b515b6d82c5ef537e285918fe7c741e
97819ce029657d6cced0f8850f47ff281c444
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = ef54a703503046d8272eaea47cfa963b696f07af04cbc6545ca16de56540
574e2bc92534ac475d6a3649f3e9cdf20a7f
BlindedElement = 026b1a0c27583dd80530b07068f05e6be0d35702db5b2d6d247
e0854beaa34d5dbc1b627a41c92dc5488e7eadb27bb8de3
EvaluationElement = 02e4c56ede2d758baf2909fc49001fc03f2795ea08151217
302844957eec43aa2eee6ac8dbc5c97e29fcab834ae58e8ad6
Proof = 4a10555cbd5ce5a0fb58a931542a6324b7a72ea5496655322e5fbc04276d
032ceafa71e351db4117e19590b464aac227b29ad3fb5f1687e994fb27d8cbb44183
34ae39203500d6794742319827708c9f799976f67a3de61e742a66af92dc218d
ProofRandomScalar = 0cdd9475ad6d9e630235ff21b634bc650bf837aaa273530d
c66aa53bb9adb4f0ed499871eb81ae8c1af769a56d4fc42b
Output = fb538f84dae5f214c5adfcf529c6fe63bc46d6a4073d540cf0dabcc7c8e
0f3c1b43b606002a9aa52ae158a19d900c136
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 485cccf5018abbf875b8e81c5ade0def4fe6fa8dfc15388367a60f23616c
d1468dae601875f7dd570624d0ae9d7be2e7,b0d53a6f8da29c3cf4f8695135d6454
24c747bec642bc91375ff142da4687426b0b4f35c14eb2477c52e1ffe177f193b
BlindedElement = 03a70754f3fefdc41235951102436ddeb3db7a37dff2c090df6
3e37604f4562bf622d3bbdd8e95d442194a3f61b800dd95,02ed7aa3d06568048bb1
7108e79a4d05158cbc027114e8fee207b571e9bc7b41e59a5316d113c07f5a80d681
44039bde78
EvaluationElement = 03ee6abfccbc76cf6ffcef6fcb5e01c491c726243bf0884c
c6e73acedc05ba47f8cefcd0e7915bf7472ac9fb8550a6084b,0398fca2cfc5d3a31
ee8f89fe4bb05adc8631aad6453b9e6c9797914d6550e2270f27c27fe79bd7aebd3e
6e4c0c1e92806
Proof = 577a90159f8dfb8f6669372430036ef7609472ac8335459974b9d590c4c0
9cfb49613b3582d008debf1ffeefc7e189f97eaa17094e7f83dfa34ea222a498b39c
570ff618bbb2e273fc03addc91dc200324872b1dea1af0476a1c57ef935e0296
ProofRandomScalar = b36f4c2a140b7a3c53dd8efb6171d3bb4d73591be8483a1a
38e40c13a04b0f2180dda3c36e3d43c3a8f127158d010945
Output = 7eb3cc88d920431c3a5ea3fb6e36b515b6d82c5ef537e285918fe7c741e
97819ce029657d6cced0f8850f47ff281c444,fb538f84dae5f214c5adfcf529c6fe
63bc46d6a4073d540cf0dabcc7c8e0f3c1b43b606002a9aa52ae158a19d900c136
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
KeyInfo = 74657374206b6579
skSm = 0fcba4a204f67d6c13f780e613915f755319aaa3cb03cd20a5a4a6c403a48
12a4fff5d3223e2c309aa66b05cb7611fd4
pkSm = 03a571100213c4356177af14a7039cfee270ad1f9abde42ac3418c501209e
d7b2fc0d4aa3373c12ba956fb555b02843fc8
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 9572d3a8a106f875023c9722b2de94efaa02c8e46a9e48f3e2ee00241f9a
75f3f7493200a8a605644334de4987fb60da
BlindedElement = 039033f6f8af673a01c079f8e6c8f3482b26cde89921f076940
97ea436be759b8763a2693e5308a59dd7e5402320ab4007
EvaluationElement = 0271667cbbf285a9597799334698305e6d253355d690822f
374e4881a831de379d174e0c1fc2e32d1d1455ce832fbd83a5
Proof = c3797deb4486e9db226367a033ff91ce45e6052b18cd1c80e19022c06350
a3bf6a8486ab608a3d09d76398e37838432978b2407f8a4f6af748262003001c9d63
8e8b73c0267d83e6ca9bce0ad28c1cde84bd6ace03d8fcaa9af554050c2850b9
ProofRandomScalar = 7e82569cb56d97e9c20e59311bac3a50735d573abb787b25
1879b77de4df554c91e25e117919a9db2af19b32ce0d501d
Output = fa15c0fe8706ac256dfd3c38d21ba0cd57b927cfcf3e4d6d5554ec1272e
670079b95cdbb2778e0df22baf50f33e12607
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01e6e57b7ec6752a45c74f3ed36a3eb8ad0dafb634f668e415357a04fab5
01c0f6764e854701129e38071b008286c5fc
BlindedElement = 02960267b046dde26458e6b132d691c58f9cf35e3abb433112a
6b0aae93aead53547fdc86c7b162902fe02766dc7ff7b48
EvaluationElement = 02d212136a764b11d854f70def6390a2715a133b65e4974d
bee1c1552bb63f838051895eb5257674ae4169ad08e09880ee
Proof = 5528bd1f017ada94f7cff5ef23d58c4707aca9519edd8d05fe45f77d50fe
ae4babedf202f3e5ffe263242d1cc10af9549e9e9a983099fc45209934240590c926
1b92da16f3bf4c5adf300a9923071c31ba5ddfceca857585e86925473a1cff12
ProofRandomScalar = 6b61028c0ce57aa6729d935ef02e2dd607cb7efcf4ae3bba
c5ec43774e65a9980f648a5af772f5e7337fbeefbee276ca
Output = 77cb533216c32cac017d706d5f0ee4630bcb0bfefbb980d95e98dc240ab
c70a944a44cde69b805aee3a39b2eb7d834be
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = ebd2fec41edafcba833ccaac567c14d2fa01f55b33a2fbbb37118f2f5603
b1298346e02cbdf55c95ef9b1aadda5ef281,be210603388cbcabb8cb630aa1ad04d
73e349009a438ce248380bd4b7e6758211fe9692922fb61f00f1a39bc735cefce
BlindedElement = 03770caa16d6f010296634a3e5efd15854cafa417bddff5d485
32c2e44d774aa6a7695f2608284c87e13afaae11029d4ee,03def601a0e7dff867d3
3ed8b52487893b184ef351c963de1708397e0902656a97e9e9fee6351da9b5d6d4d2
808d5b7d24
EvaluationElement = 026e87985e8bc38bbecedd9db5cb17fa2f44252b744cd3a0
245ef78e9bb8b21c9cd07ed58980bcb3f636580b3e7df450f1,02a6aea2be3be70cf
6c9df63324faf3c0339acce9dc4067e068ed68d8b6b06ee0faf6e579c880765e8c92
88d2a7a6a13e3
Proof = 3558c04f33f0f813874bbd6b6966693c22fb6adb00d7390ee459b9816de8
ab81789a616a42012ea3477f86d715f07a4768a74de4b5905661317b279325194874
9e45c812c18fa29600785e97764f511d135becbcbe688312630c1adb4107ec13
ProofRandomScalar = c7a86f11c143a291e349b70b34e67b38fe9dc6f90b473750
87d72e891df74070810500dfd391282c15d87bacdc9867a5
Output = fa15c0fe8706ac256dfd3c38d21ba0cd57b927cfcf3e4d6d5554ec1272e
670079b95cdbb2778e0df22baf50f33e12607,77cb533216c32cac017d706d5f0ee4
630bcb0bfefbb980d95e98dc240abc70a944a44cde69b805aee3a39b2eb7d834be
~~~

## OPRF(P-521, SHA-512)

### OPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 0152e55f3a5d836ab6c2091a904ba4b4f92e51ba59ecc211b4fc771f7c6c8
b17fcbbb2bed8a65afd7811ceeec3eac83df6a58515b6d3c71ee0ffc349e28c3fb78
d83
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 00b638b3000884019316267eae9b424f812592e4dc9cd7f7aebfb1d3d2b8
c7fa7904503aef20c694a01d3e1154fe98e7232be9eaec5789a012a559367b1f9965
4ddf
BlindedElement = 030133b29bcd167698635c7c7d7d7d79a69cabfefbe3b10d924
ab2f455e1c06bf217ad6c74fdc0d2aedcdf74da149c7b7805ab56159cd16c64f998c
32f3c6b5b92dd41
EvaluationElement = 0301c697cdf880ce990e396fe1fbc6ad09eca90416a0d4a7
dd86915521e28972caee7abcd27d096917cdeed4ae2179435a4e1953726fc63dfa17
56dc0970be2fedd34f
Output = ddcaaceceec790f4858a09f3e06e74e8b0841681a3d45ab1393d0948379
43f782d9ed22ae716a642d4ee428ddf1dae9ff631047864b99a305412aceb7efafa3
2
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 00219598d5f1544830f9d667b683234c68ef3db95227fe3ebdfd963d0307
0055fef107bfeb3c79c86b934061f894227b23a69eb0b53f168a4a2230ef6a7d703a
c4ce
BlindedElement = 0300ac450849ab04f3a58c0b7e6a9267e1c29682ca915e667f8
02f2b293a4be8d88f56e0de8e2e1888aafe6ee5cdea96749dbe701d84548de306378
d9ec4ffa5640c37
EvaluationElement = 030030046ea835ea4c896ac8041fae78b247028f502d5c63
cba2cd1235cbcc6dfe2dd623651944fd0bb8fd609cdda03702196a0b113d4c5fad3a
63847b9913f6f437c1
Output = 287712c6dbed773f39925fec0ad686dfda4a679cc7e88fa60ba9d3a7d71
2a11d4a0445995391ba56cfb018922e0d4bb4b25ec0965a33170c9b00f45c361b021
5
~~~

### VOPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 00fb5507f94782c5b72acc16b9eb21064f86b4aa525b9865258d157b0431a
b5c3515fc975fa19ddb28129c969992b31d8946c4e354bc49458bb25fae58f10ac3f
678
pkSm = 0301322c63ad53e079791739169e011f362f4396a8e93fceeee9cd814d471
80e75ffd717820fe9e9c763fa595340cd80989c31fbd0200572080752c73b80b7532
2f300
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Blind = 01dd6b45efbc57c5f087181c9f03d5b5e51b3a90cc9da17604b2e59a9375
9eb0985d2259c20e3783be009527adf47f8fb5b1437cba7731c34ac70bc6ab1b8c14
ff42
BlindedElement = 02015d40f523afdcce575dd6a39d627c01ab7d42ad6146c85f3
1e8788468f7b6c906a3cc7eb7d2d63577e31b3a71a0a8892b14a5bbd19f77b8957d7
f5c2e712a1dd122
EvaluationElement = 0300bf8707e37f7432d71e374b7af0d62fe4b17138f8f969
4272dcb7e050de7be11a5143713160ed4b4e64d560c9d290aa1a8d8725646001280f
fda0d3a39d7ed9c2c0
Proof = 005e4899066046c50b44883ad18721df558515d87514c9208b2f7c447759
473271c87748bfe659d70c954aae5d8f7040a698055f548373130ae81c1df17dc14b
918d0146611aec8e6dfe37135008d9792b8a10ff65aa5f515844461065991c1fc917
c39f6bd05a53bff30529af4247bf3efd2d1e6e6a67071795f48d9c864d6c4e39aaa7
ProofRandomScalar = 01ce330164821b9b2a108e3ef8964622075015ac9ea0f838
0dcce04b4c70b85f82bd8d1806c3f85daa0e690689a7ed6faa65712283a076c4eaee
988dcf39d6775f40
Output = 16a9387153bf7fa2c733d42f299877324cfce3b39093e72067c3d59948b
f745d77b2fe9180ffb442ec45b575eb4108d2b6f207cbfabd7bc540ad2a087cfabca
2
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 001745a97be4680b39889979a8b4b4322450628389ff2d90c0799597e99c
926ae54b2fce5ca13daa8cabbd4da53324fbd20554f2c56460442edb7d6ee76b64ab
68d1
BlindedElement = 0300b8074fcf38ca04308ecd764c09a70f3fd23ec010019c8c8
70319482c1261a436a549da3eca1e00edd3e175e07ce9155ff47fac475c983f4f415
8bd3de3e5bd0d17
EvaluationElement = 0200da275f3f8a6438b7803bea593b1189677a113efb4e07
3c6eb6912a046963e9e885eb6874479ba0a435e0ed18c08daace93c3a61d7eb9e497
bbdb7f5a9df51b9af8
Proof = 012787020d4ae60fbef04b3fe98530165b26a0b18a9936e731a37e9821d7
88a1a1abc314591dea7cae20b03d494687e833689b76fc61c77cc3f35fb2024e26e5
9be90068f24b3f2b8009a9cebfe7cdbf39a8df2d0c41f16dd36d6cecc62e40e04ba3
2226481e65a23246ff50e434074dc7c35b2a075a961c89e36f98b2c72077cc6e781a
ProofRandomScalar = 0013559a0599ff077b4ebcbe7f73e9fc1bc25fff3fc5fd6c
8bc664e27822fdece106def4a69460e9777347a314fbbe5035803d3aa65819e81997
c4d89909e25ce20e
Output = 0163635204be5347419796f3564b36d6e89c9170e4fcca5b6df79d3f676
f641b2ae3ae1a64cc49f3d788e276abe14e3c38bb2f92fdba0b45ed122a6930e7d96
1
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Blind = 017b1679ed98960e4cee27f330d5d3dccebf40596dc7e8b057938841423f
8b336f12c6c4dfa3a822d8f670e5aa46e733baaec9f93d5e14ad9ab99dfcbcb2ad15
7a8b,00010fddc6356f1aa3fb05702631e213b4bbbe8fe5176fff25526ed5b1772ba
6164952c3c2da8017fdf337f81f5cbd0ec805923a335fa1bde3dbb840b3924c5ceba
6
BlindedElement = 030110fb3a63cd993cb9aa958375cf9afed43c312bb08f80f9e
8745e6834bf2556dd84c189aab9d03da835ab29aa40ac4c3bd12aca2b1da244978b1
cfe22600f51690f,030111ddf573557fbeb29b8d8d5936fdcc27a3526a88c15acbe1
cabf9255b2173e974cd2a207e4ee8dc389db05bba89ad57667fbec5873a7bc5062e6
977a3cfd83deb9
EvaluationElement = 0201846cd86ef150d1d059151121c892628d4754757a18c8
0049d13690579420ff25c012ec16ba4ab115cd2efb85cb1ceb71a54fe7c0ca1fd55a
95421d6b7117130eb0,03011a6b29859233c384a5114bff0004dc68987211b534bad
295f831a6253c7764aa80bfafbe1a65b29f7d128f149567b788d39d4b8d7ba3e9a95
716613b047ec4392c
Proof = 016f15302d609b514e059787748cc262b6f8de41b511630041ccb020ceca
3d338c29975dea50acb2d726e8516ba789cf16cdc4e2f423c1298c63303f89d10bb1
db5900ebd8cd73abcb84055cd5b1ac377792ec3a8ccae1e5bfdab364b03fe8413eb6
28bb6c7d5b9f966742e95a1890709cd0d72c6eb9654d4f5111c11b7d718fbc64346e
ProofRandomScalar = 001caeef2365ebf9c1edbdb24825e5735614aaf644f03458
a1f30c90229f8068bec0ae930eef110e98ea1cbc6d849b4c9ca5b7a970d0320ba5f4
f95f5cd4f501d720
Output = 16a9387153bf7fa2c733d42f299877324cfce3b39093e72067c3d59948b
f745d77b2fe9180ffb442ec45b575eb4108d2b6f207cbfabd7bc540ad2a087cfabca
2,0163635204be5347419796f3564b36d6e89c9170e4fcca5b6df79d3f676f641b2a
e3ae1a64cc49f3d788e276abe14e3c38bb2f92fdba0b45ed122a6930e7d961
~~~

### POPRF Mode

~~~
Seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
KeyInfo = 74657374206b6579
skSm = 01e0993daeb97f8fc8176089e4e6adb4c03dc9b18daf7e976ed7fa6f3cb89
c40c6a84156f20371ef23bfe6e049423244d7d746c79ad380ac7fe285aba162419e9
012
pkSm = 0301264d23f5d1d615f9747d2a7177a419dabde6ca0f5a047979dbe9bce33
7241b7d2959025476f354c4f57017363d667b83b691fad8c172959963e6000de9533
f187a
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 00dc9f04fb076cffe7d179d692a05b0c2210b6c008c1062c1e54514ef654
eefc0519dd1867571c9d518e305fdf463231b6ec8b7498e2122a7a6033b6261a1696
a773
BlindedElement = 0201838e39ba54efda4db14ae369cc89caac555a83143078e7e
9902cb8b5a0972394836619904408e2e33849e15420db1ecaab9ac562e3f0ea176d0
72ba01e4d5ceae1
EvaluationElement = 0201b8a2e944fc5c149afe2cac721d9d44f0c9de83898fe5
4ad31caa293003902671ac2d241798c34d3d8c2eca81c45c6e990ce17aaa17592793
b14f01672653c6955c
Proof = 0027083be17ff3700148b1be7ee007bc7d27bcd9e750ce7f81ce146fd854
a2d55c170296b756c30f049d96045c5a99d48246c9ff3dc73528bd577a6ead8ab002
e1330038fbc2771f4b7a192faa5db03e43d4a9ea3012db8556492a31d3b603b20c67
9cb2c73969952a201f21a6931577699faa8d5a302117a28beb6b0190fb133b5efc1a
ProofRandomScalar = 00c07a53a1c70f44466b3861be4f8ef48c2bb1aec2e478e3
41c467fd4a2638aeca63ed6c4bc48d008bca3f36f043e0eb73a44aba77e5e37d5ab1
389e09b80a34cfaa
Output = 3be90ca19fbe2fc250de62792c7cf4b6b5555c8655fce1694fc7563d5d4
c5001efd1e91fbbaea31d75e33dbdefe57420c395f1ac805cc0095c4d81a0beddcb0
1
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 0085ad3fc8c91caec3bd7699591b10d6da93877a470e128f38030627dffc
bbf1f576b38677841fc47af778f9d85ac9bce6279388ddf4607e295e64cea6f4f950
78b8
BlindedElement = 0201e1ff247dd697b436a67f14c5cdae20b65a2e381de4d5793
e8d9b01adce7bad1cd75f2410a687bf4014f39873c3a261593f2104958ba24aaf2a1
0ef0754428eb6a2
EvaluationElement = 0301fd0777f77845d4d35dd83b37aac92b2cfd87f17e34ce
d3896d074d37eed66b8fb145efa4566028baed7df75d899a8c314d13b693f9b77fc0
b3ab4340514024cc2a
Proof = 0042ffc7538cae4b0f36dddedb7f23ee5934a9b12d4c261eb5d6b03c5ef2
0bec13aabd15d5e31701a951e6620c5bc4dbce90c4b9c9ce2500fff9d09711ab2e79
2a8b016b672170239fc6c530434705c9eb7faa555db47e88771dc3d529d9b38b6734
e90e8f053a1088de437c76d6fa14e5587472fb10647baa08e2e4e53f0bcb1a1dcedd
ProofRandomScalar = 003a09eed29f2e7f8950d766270d390db7a53b8080b89cb9
e024e1e008d83bd90e94f501281b6b49c351c959348b3a65f24c6f74e77a62905a6d
3e4b0b10600a7cbc
Output = 1d90446522e3c131e90be2e4f372959ae5ab4f25ca98e83e5e62d6336c4
8b5ec22fc6083d2b050cad2bbc22ae7115c2b934d965ffe74aaa43c905cd2af76728
d
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 019dd87ebabccec2627d4006b698d9ba57f6e207c989448d39fe0431e60c
9a9a4110596d5a16fa6cdf3f66467524f295b5dc8f3492c6da02dd7387bd1dc40065
b232,00adaeeed48a6f9a8fb57640c3bff88d3ab3cc52ef969f02beaba2c6e32c2f3
7baaf4ee9c691833dc081e2a0fb6ff636525457a21c1fc56bf3514635ac7fb8618f7
3
BlindedElement = 0201a2d5d6888cea12f334d54ec47e43464df9621f4c772f4f5
ac3df0b3f3654cedb22765e1b8255ed5f1b005ffa89f1b714441ebf3c4e57444f498
dbd5f40ac19ea54,0300560090b615b9a08167983486cdff98e10139960e7db1e30e
b46a7acb18167bc798d1e0cd395770360cda591871aab2d5d0235ef02567784e78c9
18d3015200d160
EvaluationElement = 020180c9b660af4783671afe3e59047d191fd16081404fd4
9bbb51eac13220beb37e1ed7b9d377caa8fde76e22a26ad3a236ccb0b2f808aa3f71
94bbc69b2732eb1c8a,0200b2ad41193242cbd6730d094105eab000d6093d8fed152
898f85d0b09b3338881c98770b1ab2dfe07079a6db9e802a94739a04a8f6bdc59436
affb65d2c09613372
Proof = 0101346f4fe3c70a1e50afc5f1219e77840aa65ecf85d9483e83286da61a
d105218ca459f24e23d36661822a493dd3adc4d90130b77b053a987bdd3976ab8576
906d00dca8a645f4484ce3bf80ee5b0a77539a150e98fe25c146b26fccaaa2387cac
04604f8b3f31508ee0c46f978d2262cd23e509a835c74a2a5bed2ab2161236a61f09
ProofRandomScalar = 010a82559ee5e4ba79c390c4033405e3f792bc49daa905c6
94707e7e0191104b34d68c7cc81c2e392da60b838eadf434b693d9b4f7c7beb31e37
008156656c19382b
Output = 3be90ca19fbe2fc250de62792c7cf4b6b5555c8655fce1694fc7563d5d4
c5001efd1e91fbbaea31d75e33dbdefe57420c395f1ac805cc0095c4d81a0beddcb0
1,1d90446522e3c131e90be2e4f372959ae5ab4f25ca98e83e5e62d6336c48b5ec22
fc6083d2b050cad2bbc22ae7115c2b934d965ffe74aaa43c905cd2af76728d
~~~
