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
    email: adavidson@cloudflare.com
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
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: cawood@apple.com

normative:
  RFC2104:
  RFC2119:
  RFC5869:
  RFC7748:
  I-D.irtf-cfrg-hash-to-curve:
  NIST:
    title: Keylength - NIST Report on Cryptographic Key Length and Cryptoperiod (2016)
    target: https://www.keylength.com/en/4/
    date: false
  PrivacyPass:
    title: Privacy Pass
    target: https://github.com/privacypass/challenge-bypass-server
    date: false
  ChaumPedersen:
    title: Wallet Databases with Observers
    target: https://chaum.com/publications/Wallet_Databases.pdf
    date: false
    authors:
        -
          ins: D. Chaum
          org: CWI, The Netherlands
        -
          ins: T. P. Pedersen
          org: Aarhus University, Denmark
  ChaumBlindSignature:
    title: Blind Signatures for Untraceable Payments
    target: http://sceweb.sce.uhcl.edu/yang/teaching/csci5234WebSecurityFall2011/Chaum-blind-signatures.PDF
    date: false
    authors:
      -
        ins: D. Chaum
        org: University of California, Santa Barbara, USA
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
  JKKX17:
    title: >
      TOPPSS: Cost-minimal Password-Protected Secret Sharing based on Threshold OPRF
    target: https://eprint.iacr.org/2017/363
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
  RISTRETTO:
    title: The ristretto255 Group
    target: https://tools.ietf.org/html/draft-hdevalence-cfrg-ristretto-01
    date: false
    authors:
      -
        ins: H. de Valence
      -
        ins: J. Grigg
      -
        ins: G. Tankersley
      -
        ins: F. Valsorda
      -
        ins: I. Lovecruft
  DECAF:
    title: Decaf, Eliminating cofactors through point compression
    target: https://www.shiftleft.org/papers/decaf/decaf.pdf
    date: false
    authors:
      -
        ins: M. Hamburg
        org: Rambus Cryptography Research
  OPAQUE:
    title: The OPAQUE Asymmetric PAKE Protocol
    target: https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-02
    date: false
    authors:
      -
        ins: H. Krawczyk
        org: IBM Research
  SHAKE:
    title: SHA-3 Standard, Permutation-Based Hash and Extendable-Output Functions
    target: https://www.nist.gov/publications/sha-3-standard-permutation-based-hash-and-extendable-output-functions?pub_id=919061
    date: false
    authors:
      -
        ins: Morris J. Dworkin
        org: Federal Inf. Process. Stds. (NIST FIPS)
  SEC2:
    title: "SEC 2: Recommended Elliptic Curve Domain Parameters"
    target: http://www.secg.org/sec2-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)
  keytrans:
    title: "Security Through Transparency"
    target: https://security.googleblog.com/2017/01/security-through-transparency.html
    date: false
    authors:
      -
        ins: Ryan Hurst
        org: Google
      -
        ins: Gary Belvin
        org: Google

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
function with secret key k on input x. Roughly, F is pseudorandom if the
output y = F(k, x) is indistinguishable from uniformly sampling any
element in F's range for random choice of k. An oblivious PRF (OPRF) is
a two-party protocol between a prover P and verifier V where P holds a
PRF key k and V holds some input x. The protocol allows both parties to
cooperate in computing F(k, x) with P's secret key k and V's input x
such that: V learns F(k, x) without learning anything about k; and P
does not learn anything about x. A Verifiable OPRF (VOPRF) is an OPRF
wherein P can prove to V that F(k, x) was computed using key k, which is
bound to a trusted public key Y = kG. Informally, this is done by
presenting a non-interactive zero-knowledge (NIZK) proof of equality
between (G, Y) and (Z, M), where Z = kM for some point M.

OPRFs have been shown to be useful for constructing: password-protected
secret sharing schemes {{JKK14}}; privacy-preserving password stores
{{SJKS17}}; and password-authenticated key exchange or PAKE {{OPAQUE}}.
VOPRFs are useful for producing tokens that are verifiable by V. This
may be needed, for example, if V wants assurance that P did not use a
unique key in its computation, i.e., if V wants key consistency from P.
This property is necessary in some applications, e.g., the Privacy Pass
protocol {{PrivacyPass}}, wherein this VOPRF is used to generate
one-time authentication tokens to bypass CAPTCHA challenges. VOPRFs have
also been used for password-protected secret sharing schemes e.g.
{{JKKX16}}.

This document introduces an OPRF protocol built in prime-order groups,
applying to finite fields of prime-order and also elliptic curve (EC)
settings. The protocol has the option of being extended to a VOPRF with
the addition of a NIZK proof for proving discrete log equality
relations. This proof demonstrates correctness of the computation using
a known public key that serves as a commitment to the server's secret
key. The document describes the protocol, its security properties, and
provides preliminary test vectors for experimentation. The rest of the
document is structured as follows:

- {{background}}: Describe background, related work, and use cases of
  OPRF/VOPRF protocols.
- {{properties}}: Discuss security properties of OPRFs/VOPRFs.
- {{protocol}}: Specify an authentication protocol from OPRF
  functionality, based in prime-order groups (with an optional
  verifiable mode). Algorithms are stated formally for OPRFs in {{oprf}}
  and for VOPRFs in {{voprf}}.
- {{dleq}}: Specify the NIZK discrete logarithm equality (DLEQ)
  construction used for constructing the VOPRF protocol.
- {{batch}}: Specifies how the DLEQ proof mechanism can be batched for
  multiple VOPRF invocations, and how this changes the protocol
  execution.
- {{ciphersuites}}: Considers explicit instantiations of the protocol in
  the elliptic curve setting.
- {{sec}}: Discusses the security considerations for the OPRF and VOPRF
  protocol.
- {{apps}}: Discusses some existing applications of OPRF and VOPRF
  protocols.
- {{testvecs}}: Specifies test vectors for implementations in the
  elliptic curve setting.

## Change log

[draft-01](https://tools.ietf.org/html/draft-irtf-cfrg-voprf-00):

- Updated ciphersuites to be in line with
  https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04
- Made some necessary modular reductions more explicit

## Terminology {#terminology}

The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- OPRF: Oblivious PRF.
- VOPRF: Verifiable Oblivious Pseudorandom Function.
- Verifier (V): Protocol initiator when computing F(k, x), also known as
  client.
- Prover (P): Holder of secret key k, also known as server.
- NIZK: Non-interactive zero knowledge.
- DLEQ: Discrete Logarithm Equality.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

# Background {#background}

OPRFs are functionally related to blind signature schemes. In such a
scheme, a client can receive signatures on private data, under the
signing key of some server. The security properties of such a scheme
dictate that the client learns nothing about the signing key, and that
the server learns nothing about the data that is signed. One of the more
popular blind signature schemes is based on the RSA cryptosystem and is
known as Blind RSA {{ChaumBlindSignature}}.

OPRF protocols can thought of as symmetric alternatives to blind
signatures. Essentially the client learns y = PRF(k,x) for some input x
of their choice, from a server that holds k. Since the security of an
OPRF means that x is hidden in the interaction, then the client can
later reveal x to the server along with y.

The server can verify that y is computed correctly by recomputing the
PRF on x using k. In doing so, the client provides knowledge of a
'signature' y for their value x. The verification procedure is thus
symmetric as it requires knowledge of the key k. This is discussed more
in the following section.

# Preliminaries

We start by detailing some necessary cryptographic definitions.

## Security Properties {#properties}

The security properties of an OPRF protocol with functionality y = F(k,
x) include those of a standard PRF. Specifically:

- Pseudorandomness: F is pseudorandom if the output y = F(k,x) on any
  input x is indistinguishable from uniformly sampling any element in
  F's range, for a random sampling of k.

In other words, for an adversary that can pick inputs x from the domain
of F and can evaluate F on (k,x) (without knowledge of randomly sampled
k), then the output distribution F(k,x) is indistinguishable from the
uniform distribution in the range of F.

A consequence of showing that a function is pseudorandom, is that it is
necessarily non-malleable (i.e. we cannot compute a new evaluation of F
from an existing evaluation). A genuinely random function will be
non-malleable with high probability, and so a pseudorandom function must
be non-malleable to maintain indistinguishability.

An OPRF protocol must also satisfy the following property:

- Oblivious: P must learn nothing about V's input or the output of the
  function. In addition, V must learn nothing about P's private key.

Essentially, obliviousness tells us that, even if P learns V's input x
at some point in the future, then P will not be able to link any
particular OPRF evaluation to x. This property is also known as
unlinkability {{DGSTV18}}.

Optionally, for any protocol that satisfies the above properties, there
is an additional security property:

- Verifiable: V must only complete execution of the protocol if it can
  successfully assert that the OPRF output computed by V is correct,
  with respect to the OPRF key held by P.

Any OPRF that satisfies the 'verifiable' security property is known as a
verifiable OPRF, or VOPRF for short. In practice, the notion of
verifiability requires that P commits to the key k before the actual
protocol execution takes place. Then V verifies that P has used k in the
protocol using this commitment. In the following, we may also refer to
this commitment as a public key.

## Prime-order group instantiation

In this document, we assume the construction of a prime-order group GG
for performing all mathematical operations. Such a group MUST provide
the interface provided by cyclic group under the addition operation (for
example, well-defined addition of group elements). We also assume the
presence of a fixed generator G that can be detailed as a fixed
parameter in the description of the group. We write p = order(GG) to
represent the order of the group throughout this document.

It is common in cryptographic applications to instantiate such
prime-order groups using elliptic curves, such as those detailed in
{{SEC2}}. For some choices of elliptic curves (e.g. those detailed in
{{RFC7748}} require accounting for cofactors) there are some
implementation issues that introduce inherent discrepancies between
standard prime-order groups and the elliptic curve instantiation. In
this document, all algorithms that we detail assume that the group is a
prime-order group, and this MUST be upheld by any implementer. That is,
any curve instantiation shoudl be written such that any discrepancies
with a prime-order group instantiation are removed. In the case of
cofactors, for example, this can be done by building cofactor
multiplication into all elliptic curve operations.

## Conventions

We detail a list of conventions that we use throughout this document.

### Binary strings

- We use the notation x <-$ Q to denote sampling x from the uniform
  distribution over the set Q.
- We use x <- {0,1}^u to denote sampling x uniformly from the set of
  binary strings of length u. We may interpret x afterwards as a byte
  array.
- We say that x is a binary string of arbitrary-length (or alternatively
  sampled from {0,1}^*) if there is no fixed-size requirement on x.
- For two byte arrays x & y, write x .. y to denote their concatenation.

### Group notation

- We use the letter p to denote the order of a group GG throughout,
  where the instantiation of the specific group is defined by context.
- For elements A & B of GG, we write A + B to denote the addition of thr
  group elements.
- We use GF(p) to denote the Galois Field of scalar values associated
  with the group GG.
- For a scalar r in GF(p), and a group element A, we write rA to denote
  the scalar multiplication of A.
- For two scalars r, s in GF(p), we use r+s to denote the resulting
  scalar in GF(p) (we may optionally write r+s mod p to make the modular
  reduction explicit).

# OPRF Protocol {#protocol}

In this section we describe the OPRF and VOPRF protocols. Recall that
such a protocol takes place between a verifier (V) and a prover (P).
Commonly, V is a client and P is a server, and so we use these names
interchangeably throughout. We always operate under the assumption that
the verifier is a client, and the prover is a server in the interaction
(and so we will use these names interchangeably throughout). The server
holds a secret key k for a PRF. The protocol allows the client to learn
PRF evaluations on chosen inputs x in such a way that the server learns
nothing of x.

Our OPRF construction is based on the VOPRF construction known as
2HashDH-NIZK given by {{JKK14}}; essentially without providing
zero-knowledge proofs that verify that the output is correct. Our VOPRF
construction (including the NIZK DLEQ proofs from {{dleq}}) is identical
to the {{JKK14}} construction. With batched proofs ({{batch}}) our
construction differs slightly in that we can perform multiple VOPRF
evaluations in one go, whilst only constructing one NIZK proof object.

In this section we describe the OPRF and VOPRF protocols. Recall that
such a protocol takes place between a verifier (V) and a prover (P). We
may commonly think of the verifier as the client, and the prover as the
server in the interaction (we will use these names interchangeably
throughout). The server holds a key k for a PRF. The protocol allows the
client to learn PRF evaluations on chosen inputs x without revealing x
to the server.

Our OPRF construction is based on the VOPRF construction known as
2HashDH-NIZK given by {{JKK14}}; essentially without providing
zero-knowledge proofs that verify that the output is correct. Our VOPRF
construction (including the NIZK DLEQ proofs from {{dleq}}) is identical
to the {{JKK14}} construction. With batched proofs ({{batch}}) our
construction differs slightly in that we can perform multiple VOPRF
evaluations in one go, whilst only constructing one NIZK proof object.

## Design

Let GG be an additive group of prime-order p, let GF(p) be the Galois
field defined by the integers modulo p. Define distinct hash functions
H_1 and H_2, where H_1 maps arbitrary input onto GG (H_1: {0,1}^* -> GG)
and H_2 maps two arbitrary inputs to a fixed-length (w) output (H_2:
{0,1}^u x {0,1}^v -> {0,1}^w), e.g., HMAC_SHA256. All hash functions in
the protocol are modeled as random oracles. Let L be the security
parameter. Let k be the prover's secret key, and Y = kG be its
corresponding 'public key' for some fixed generator G taken from the
description of the group GG. This public key Y is also referred to as a
commitment to the OPRF key k, and the pair (G,Y) as a commitment pair.
Let x be the binary string that is the verifier's input to the OPRF
protocol (this can be of arbitrary length).

The OPRF protocol begins with V blinding its input for the OPRF
evaluator such that it appears uniformly distributed GG. The latter then
applies its secret key to the blinded value and returns the result. To
finish the computation, V then removes its blind and hashes the result
(along with a domain separating label DST) using H_2 to yield an output.
This flow is illustrated below.

~~~
     Verifier(x)                   Prover(k)
  ----------------------------------------------------------
     r <-$ GF(p)
     M = rH_1(x) mod p
                           M
                        ------->
                                  Z = kM mod p
                                  [D = DLEQ_Generate(k,G,Y,M,Z)]
                          Z[,D]
                        <-------
    [b = DLEQ_Verify(G,Y,M,Z,D)]
    N = Zr^(-1) mod p
    Output H_2(DST, x .. N) mod p [if b=1, else "error"]
~~~

Steps that are enclosed in square brackets (DLEQ_Generate and
DLEQ_Verify) are optional for achieving verifiability. These are
described in {{dleq}}. In the verifiable mode, we assume that P has
previously committed to their choice of key k with some values (G,Y=kG)
and these are publicly known by V. Notice that revealing (G,Y) does not
reveal k by the well-known hardness of the discrete log problem.

Strictly speaking, the actual PRF function that is computed is:

~~~
F(k, x) = N = kH_1(x)
~~~

It is clear that this is a PRF H_1(x) maps x to a random element in GG,
and GG is cyclic. This output is computed when the client computes
Zr^(-1) by the commutativity of the multiplication. The client finishes
the computation by outputting H_2(DST, x .. N). Note that the output
from P is not the PRF value because the actual input x is blinded by r.

The security of our construction is discussed in more detail in
{{protocol-sec}}. We discuss the considerations that should be made when
embedding (V)OPRF protocols into wider protocols in {{embed}}.

## Protocol functionality

This protocol may be decomposed into a series of steps, as described
below:

- Setup(l): Let GG=GG(l) be a group with a prime-order p=p(l) (e.g., p
  is l-bits long). Randomly sample an integer k in GF(p) and output
  (k,GG)
- Blind(x): Compute and return a blind, r, and blinded representation of
  x in GG, denoted M.
- Evaluate(k,M,h?): Evaluates on input M using secret key k to produce
  Z, the input h is optional and equal to the cofactor of an elliptic
  curve. If h is not provided then it defaults to 1.
- Unblind(r,Z): Unblind blinded OPRF evaluation Z with blind r, yielding
  N and output N.
- Finalize(x,N,aux): Finalize N by first computing dk := H_2(DST, x ..
  N). Subsequently output y := H_2(dk, aux), where aux is some auxiliary
  data.

For verifiability (VOPRF) we modify the algorithms of VerifiableSetup,
VerifiableEvaluate and VerifiableUnblind to be the following:

- VerifiableSetup(l): Run (k,GG) = Setup(l), compute Y = kG, where G is
  a generator of the group GG. Output (k,GG,Y).
- VerifiableEvaluate(k,G,Y,M,h?): Evaluates on input M using secret key
  k to produce Z. Generate a NIZK proof D = DLEQ_Generate(k,G,Y,M,Z),
  and output (Z, D). The optional cofactor h can also be provided, as in
  Evaluate.
- VerifiableUnblind(r,G,Y,M,Z,D): Unblind blinded OPRF evaluation Z with
  blind r, yielding N. Output N if 1 = DLEQ_Verify(G,Y,M,Z,D).
  Otherwise, output "error".

We leave the rest of the OPRF algorithms unmodified. When referring
explicitly to VOPRF execution, we replace 'OPRF' in all method names
with 'VOPRF'. We describe explicit instantiations of these functions in
{{oprf}} and {{voprf}}.

### Generalized OPRF {#general-oprf}

Using the API provided by the functions above, we can restate the OPRF
protocol using the following descriptions. The first protocol refers to
the OPRF setup phase that is run by the server. This generates the
secret input used by the server and the public information that is given
to the client.

OPRF setup phase:

~~~
     Verifier()                   Prover(l)
  ----------------------------------------------------------
                                  (k,GG) = Setup(l)
                           GG
                        <-------
~~~

OPRF evaluation phase:

~~~
     Verifier(x,aux)                   Prover(k)
  ----------------------------------------------------------
     (r, M) = Blind(x)
                            M
                        ------->
                                  Z = Evaluate(k,M)
                            Z
                        <-------
    N = Unblind(r,Z)
    Output Finalize(x,N,aux)
~~~

Note that in the final output, the client computes Finalize over some
auxiliary input data aux.

### Generalized VOPRF {#general-voprf}

The generalized VOPRF functionality differs slightly from the OPRF
protocol above. Firstly, the server sends over an extra commitment value
Y = kG, where G is a common generator known to both participants.
Secondly, the server sends over both outputs from VerifiableEvaluate in
the evaluation phase, and the client also verifies the server's output.

VOPRF setup phase:

~~~
     Verifier()                   Prover(l)
  ----------------------------------------------------------
                                  (k,GG,Y) = VerifiableSetup(l)
                         (GG,Y)
                        <-------
~~~

VOPRF evaluation phase:

~~~
     Verifier(x,Y,aux)            Prover(k)
  ----------------------------------------------------------
     (r, M) = VerifiableBlind(x)
                            M
                        ------->
                                  (Z,D) = VerifiableEvaluate(k,G,Y,M)
                          (Z,D)
                        <-------
    N = VerifiableUnblind(r,G,Y,M,Z,D)
    Output VerifiableFinalize(x,N,aux)
~~~

## Protocol correctness

Protocol correctness requires that, for any key k, input x, and (r, M) =
Blind(x), it must be true that:

~~~
  Finalize(x, Unblind(r,M,Evaluate(k,M)), aux)
      == H_2(H_2(DST, x .. F(k,x)), aux)
~~~

with overwhelming probability. Likewise, in the verifiable setting, we
require that:

~~~
  Z = VerifiableEvaluate(k,G,Y,M)
  VerifiableFinalize(x, VerifiableUnblind(r,G,Y,M,Z), aux)
      == H_2(H_2(DST, x .. F(k,x)), aux)
~~~

with overwhelming probability, where (r, M) = VerifiableBlind(x). In
other words, the inner H_2 invocation effectively derives a key, dk,
from the input data DST, x, N. The outer invocation derives the output y
by evaluating H_2 over dk and auxiliary data aux.

## Instantiations of GG

As we remarked above, GG is a group with associated prime-order p. While
we choose to write operations in the setting where GG comes equipped
with an additive operation, we could also define the operations in the
multiplicative setting. In the multiplicative setting we can choose GG
to be a prime-order subgroup of a finite field FF_p. For example, let p
be some large prime (e.g. > 2048 bits) where p = 2q+1 for some other
prime q. Then the subgroup of squares of FF_p (elements u^2 where u is
an element of FF_p) is cyclic, and we can pick a generator of this
subgroup by picking G from FF_p (ignoring the identity element).

For practicality of the protocol, it is preferable to focus on the cases
where GG is an additive subgroup so that we can instantiate the OPRF in
the elliptic curve setting. This amounts to choosing GG to be a
prime-order subgroup of an elliptic curve over base field GF(p) for
prime p. There are also other settings where GG is a prime-order
subgroup of an elliptic curve over a base field of non-prime order,
these include the work of Ristretto {{RISTRETTO}} and Decaf {{DECAF}}.

We will use p > 0 generally for constructing the base field GF(p), not
just those where p is prime. To reiterate, we focus only on the additive
case, and so we focus only on the cases where GF(p) is indeed the base
field.

Unless otherwise stated, we will always assume that the generator G that
we use for the group GG is a fixed generator. This generator should be
available to both the client and the server ahead of the protocol, or
derived for each different group instantiation using a fixed method. In
the elliptic curve setting, we recommend using the fixed generators that
are given as part of the curve description.

## OPRF algorithms {#oprf}

This section provides descriptions of the algorithms used in the
generalized protocols from {{general-oprf}}. We describe the VOPRF
analogues for the protocols in {{general-voprf}} later in {{voprf}}.

We note here that the blinding mechanism that we use can be modified
slightly with the opportunity for making performance gains in some
scenarios. We detail these modifications in Section {{blinding}}.

### Setup

~~~
Input:

 l: Some suitable choice of prime length for instantiating a group
    structure (e.g. as described in [NIST]).

Output:

 k:  A key chosen from {0,1}^l and interpreted as a scalar in [1,p-1].
 GG: A cyclic group with prime-order p of length l bits.

Steps:

 1. Construct a group GG = GG(l) with prime-order p of length l bits
 2. k <-$ GF(p)
 3. Output (k,GG)
~~~

### Blind

~~~
Input:

 x: Binary string taken from {0,1}^*.

Output:

 r: Random scalar in [1, p - 1].
 M: An element in GG.

Steps:

 1.  r <-$ GF(p)
 2.  M := rH_1(x)
 3.  Output (r, M)
~~~

### Evaluate

~~~
Input:

 k: A scalar value taken from [1,p-1].
 M: An element in GG.

Output:

 Z: An element in GG.

Steps:

 1. Z := kM
 2. Output Z
~~~

### Unblind

~~~
Input:

 r: Random scalar in [1, p - 1].
 Z: An element in GG.

Output:

 N: An element in GG.

Steps:

 1. N := (r^(-1))Z
 2. Output N
~~~

### Finalize

~~~
Input:

 x: Binary string taken from {0,1}^*.
 N: An element in GG.
 aux: Arbitrary auxiliary data (as bytes).

Output:

 y: Random element in {0,1}^L.

Steps:

 1. DST := "oprf_derive_output"
 2. dk := H_2(DST, x .. N)
 3. y := H_2(dk, aux)
 4. Output y
~~~

## VOPRF algorithms {#voprf}

We make modifications to the aforementioned algorithms in the VOPRF
setting.

### VerifiableSetup

~~~
Input:

 G: Public fixed generator of GG.
 l: Some suitable choice of key-length (e.g. as described in [NIST]).

Output:

 k:  A key chosen from {0,1}^l and interpreted as a scalar in [1,p-1].
 GG: A cyclic group with prime-order p of length l bits.
 Y:  A group element in GG.

Steps:

  1. (k,GG) <- Setup(l)
  2. Y := kG
  3. Output (k,GG,Y)
~~~

### VerifiableBlind

~~~
Input:

 x: V's PRF input.

Output:

 r: Random scalar in [1, p - 1].
 M: An element in GG.

Steps:

 1.  r <-$ GF(p)
 2.  M := rH_1(x)
 3.  Output (r,M)
~~~

### VerifiableEvaluate

~~~
Input:

 k: A random scalar in [1,p-1].
 G: Public fixed generator of group GG.
 Y: An element in GG.
 M: An element in GG.

Output:

 Z: An element in GG.
 D: DLEQ proof that log_G(Y) == log_M(Z).

Steps:

 1. Z := kM
 2. Z <- hZ
 3. D = DLEQ_Generate(k,G,Y,M,Z)
 4. Output (Z, D)
~~~

### VerifiableUnblind

~~~
Input:

 r: Random scalar in [1, p - 1].
 G: Public fixed generator of group GG.
 Y: An element in GG.
 M: An element in GG.
 Z: An element in GG.
 D: DLEQ proof object.

Output:

 N: An element in GG.

Steps:

 1. if DLEQ_Verify(G,Y,M,Z,D) == false: output "error"
 2. N := (r^(-1))Z
 3. Output N
~~~

### VerifiableFinalize

~~~
Input:

 x:   Binary string in {0,1}^*.
 N:   An element in GG, or "error".
 aux: Arbitrary auxiliary data in {0,1}^*.

Output:

 y:   Random element in {0,1}^L, or "error"

Steps:

 1. If N == "error", output "error".
 2. DST := "voprf_derive_output"
 3. dk := H_2(DST, x .. N)
 4. y := H_2(dk, aux)
 5. Output y
~~~

## Efficiency gains with pre-processing and fixed-base blinding {#blinding}

In Section {{oprf}} we assume that the client-side blinding is carried
out directly on the output of H_1(x), i.e. computing rH_1(x) for some r
<-$ GF(p). In the {{OPAQUE}} draft, it is noted that it may be more
efficient to use additive blinding rather than multiplicative if the
client can preprocess some values. For example, a valid way of computing
additive blinding would be to instead compute H_1(x)+rG, where G is the
fixed generator for the group GG.

We refer to the 'multiplicative' blinding as variable-base blinding
(VBB), since the base of the blinding (H_1(x)) varies with each
instantiation. We refer to the additive blinding case as fixed-base
blinding (FBB) since the blinding is applied to the same generator each
time (when computing rG).

By pre-processing tables of blinded scalar multiplications for the
specific choice of G it is possible to gain a computational advantage.
Choosing one of these values rG (where r is the scalar value that is
used), then computing H_1(x)+rG is more efficient than computing rH_1(x)
(one addition against log_2(r)). Therefore, it may be advantageous to
define the OPRF and VOPRF protocols using additive blinding rather than
multiplicative blinding. In fact, the only algorithms that need to
change are Blind and Unblind (and similarly for the VOPRF variants).

We define the FBB variants of the algorithms in {{oprf}} below along
with a new algorithm Preprocess that defines how preprocessing is
carried out. The equivalent algorithms for VOPRF are almost identical
and so we do not redefine them here. Notice that the only computation
that changes is for V, the necessary computation of P does not change.

### Preprocess

~~~
Input:

 G:  Public fixed generator of GG

Output:

 r:  Random scalar in [1, p-1]
 rG: An element in GG.
 rY: An element in GG.

Steps:

 1.  r <-$ GF(p)
 2.  Output (r, rG, rY)
~~~

### Blind

~~~
Input:

 x:  Binary string in {0,1}^*.
 rG: An element in GG.

Output:

 M: An element in GG.

Steps:

 1.  M := H_1(x)+rG
 2.  Output M
~~~

### Unblind

~~~
Input:

 rY: An element in GG.
 M:  An element in GG.
 Z:  An element in GG.

Output:

 N: An element in GG.

Steps:

 1. N := Z-rY
 2. Output N
~~~

Notice that Unblind computes (Z-rY) = k(H_1(x)+rG) - rkG = kH_1(x) by
the commutativity of scalar multiplication in GG. This is the same
output as in the original Unblind algorithm.

## Recommended protocol integration {#embed}

We describe some recommendations and suggestions on the topic of
integrating the (V)OPRF protocol from {{protocol}} into wider protocols.
It should be noted that since {{JKK14}} provides a security proof of the
VOPRF construction in the UC security model, then any UC-secure protocol
that uses the OPRF construction as an atomic instantiation will remain
UC-secure.

Thus, it is RECOMMENDED that any protocol that wishes to include an OPRF
stage does so by implementing all OPRF evaluation functionality as a
contiguous block of operations during the protocol. This does not
include the OPRF setup phase, which should be run before the entire
protocol interaction. For example, such an instantiation for a wider
protocol W would look like the following.

~~~
    ================================================================
                           OPRF setup phase
    ================================================================

    > ...
    > BEGIN(protocol W)
    > ...
    > PAUSE(protocol W)

    ================================================================
                         OPRF evaluation phase
    ================================================================

    > RESTART(protocol W)
    > ...
    > END(protocol W)
~~~

In other words, no messages from protocol W should take place during the
OPRF protocol instantiation. This DOES NOT preclude the participants in
protocol W from using the outputs of the OPRF evaluation, once the OPRF
protocol is complete. Note that the OPRF protocol can involve batched
evaluations, as well as single evaluations.

### Setup phase

In the VOPRF setting, the server must send to the client Y (the
commitment to the server key k. From this information, the client and
server must agree on a generator G for the group description. It is
important that the generator G of GG is not chosen by the server, and
that it is agreed upon before the protocol starts. In the elliptic curve
setting, we recommend that G is chosen as the standard generator for the
curve.

As we mentioned above, if an implementer wants to embed OPRF evaluation
as part of a wider protocol, then we recommend that this setup phase
should occur before all communication takes place; including all
communication required for the wider protocol. We recommend that any
server implementation only implements one group instantiation at any one
time. This means that the client does not have to pick a specific
instantiation when it sends the first evaluation message.

### Evaluation phase

The evaluation phase of the OPRF results in a client receiving
pseudorandom function evaluations from the server. It is important that
the client is able to link the computation that it performs in the first
step, with the output that it receives from the server. In other words,
the client must store the data (r,M) output by Blind(x). When it
receives Z from the server, it must then use (r,M) as inputs to Blind.

In the batched setting, the client stores multiple values (ri,Mi) and
sends each Mi to the server. Both client and server should preserve this
ordering throughout the evaluation phase so that the client can
successfully finalize the output in the final step.

### Additional requirements

The client input to the OPRF evaluation phase is a set of bytes x. These
bytes are RECOMMENDED to be uniformly distributed. If the bytes are
sampled from a predictable distribution instead, then it is likely that
the server will also be able to predict the client's input to the OPRF.
Therefore client privacy is reduced.

Protocols that embed an OPRF evaluation MUST specify exactly how group
elements are encoded in messages.

The server need not not preserve any information during the evaluation
exchange. For efficiency and client-privacy reasons, we recommend that
all data received from the client in the evaluation phase is destroyed
after the server has responded.

In the VOPRF setting, when the server sends the response, it needs to
indicate which version of key that it has used. This enables the client
to retrieve the correct commitment from the public registry. The server
MUST include a key identifier as part of its response, to ensure that
the client can verify the contents of D correctly.

# NIZK Discrete Logarithm Equality Proof {#dleq}

For the VOPRF protocol we require that V is able to verify that P has
used its private key k to evaluate the PRF. We can do this by showing
that the original commitment (G,Y) output by VerifiableSetup(l)
satisfies log_G(Y) == log_M(Z) where Z is the output of
VerifiableEvaluate(k,G,Y,M).

This may be used, for example, to ensure that P uses the same private
key for computing the VOPRF output and does not attempt to "tag"
individual verifiers with select keys. This proof must not reveal the
P's long-term private key to V.

Consequently, this allows extending the OPRF protocol with a
(non-interactive) discrete logarithm equality (DLEQ) algorithm built on
a Chaum-Pedersen {{ChaumPedersen}} proof. This proof is divided into two
procedures: DLEQ_Generate and DLEQ_Verify. These are specified below.

## DLEQ_Generate

~~~
Input:

 k: Evaluator secret key.
 G: Public fixed generator of GG.
 Y: Evaluator public key (= kG).
 M: An element in GG.
 Z: An element in GG.
 H_3: A hash function from GG to {0,1}^L, modeled as a random oracle.

Output:

 D: DLEQ proof (c, s).

Steps:

 1. r <-$ GF(p)
 2. A := rG
 3. B := rM
 4. c <- H_3(G,Y,M,Z,A,B) (mod p)
 5. s := (r - ck) (mod p)
 6. Output D := (c, s)
~~~

We note here that it is essential that a different r value is used for
every invocation. If this is not done, then this may leak the key k in a
similar fashion as is possible in Schnorr or (EC)DSA scenarios where
fresh randomness is not used.

## DLEQ_Verify

~~~
Input:

 G: Public fixed generator of GG.
 Y: Evaluator public key.
 M: An element in GG.
 Z: An element in GG.
 D: DLEQ proof (c, s).

Output:

 True if log_G(Y) == log_M(Z), False otherwise.

Steps:

 1. A' := (sG + cY)
 2. B' := (sM + cZ)
 3. c' <- H_3(G,Y,M,Z,A',B') (mod p)
 4. Output c == c' (mod p)
~~~

# Batched VOPRF evaluation {#batch}

Common applications (e.g. {{PrivacyPass}}) require V to obtain multiple
PRF evaluations from P. In the VOPRF case, this would naïvely require
running multiple protocol invocations. This is costly, both in terms of
computation and communication. To get around this, applications can use
a 'batching' procedure for generating and verifying DLEQ proofs for a
finite number of PRF evaluation pairs (Mi,Zi). For n PRF evaluations:

- Proof generation is slightly more expensive from 2n modular
  exponentiations to 2n+2.
- Proof verification is much more efficient, from 4n modular
  exponentiations to 2n+4.
- Communications falls from 2n to 2 group elements.

Since P is the VOPRF server, it may be able to tolerate a slight
increase in proof generation complexity for much more efficient
communication and proof verification.

In this section, we describe algorithms for batching the DLEQ generation
and verification procedure. For these algorithms we require two
additional hash functions H_4: GG^(2n+2) -> {0,1}^a, and H_5: {0,1}^a x
ZZ^3 -> {0,1}^b (both modeled as random oracles).

We can instantiate the random oracle function H_4 using the same hash
function that is used for H_3 previosuly. For H_5, we can also use a
similar instantiation, or we can use a variable-length output generator.
For example, for groups with an order of 256-bit, valid instantiations
include functions such as SHAKE-256 {{SHAKE}} or HKDF-Expand-SHA256
{{RFC5869}}. This is preferable in situations where we may require
outputs that are larger than 512 bits in length, for example.

## Batched_DLEQ_Generate

~~~
Input:

 k: Evaluator secret key.
 G: Public fixed generator of group GG (with order p).
 Y: Evaluator public key (= kG).
 n: Number of PRF evaluations.
 [ Mi ]: An array of points in GG of length n.
 [ Zi ]: An array of points in GG of length n.
 H_4: A random oracle hash function from GG^(2n+2) to {0,1}^a.
 H_5: A random oracle hash function from {0,1}^a x ZZ^2 to {0,1}^b.
 label: An integer label value for the splitting the domain of H_5

Output:

 D: DLEQ proof (c, s).

Steps:

 1. seed <- H_4(G,Y,[Mi,Zi]))
 2. i' := i
 3. for i in [m]:
    1. di <- H_5(seed,i',info)
    2. if di > p:
       1. i' = i'+1
       2. i = i-1 // decrement and try again
       3. continue
 4. c1,...,cn := (int)d1,...,(int)dn
 5. M := c1M1 + ... + cnMn
 6. Z := c1Z1 + ... + cnZn
 7. Output DLEQ_Generate(k,G,Y,M,Z)
~~~

## DLEQ_Batched_Verify

~~~
Input:

 G: Public fixed generator of group GG (with order p).
 Y: Evaluator public key.
 [ Mi ]: An array of points in GG of length n.
 [ Zi ]: An array of points in GG of length n.
 D: DLEQ proof (c, s).

Output:

 True if log_G(Y) == log_(Mi)(Zi) for each i in 1...n, False otherwise.

Steps:

 1. seed <- H_4(G,Y,[Mi,Zi]))
 2. i' := i
 3. for i in [m]:
    1. di <- H_5(seed,i',info)
    2. if di > p:
       1. i' = i'+1
       2. i = i-1 // decrement and try again
       3. continue
 4. c1,...,cn := (int)d1,...,(int)dn
 5. M := c1M1 + ... + cnMn
 6. Z := c1Z1 + ... + cnZn
 7. Output DLEQ_Verify(G,Y,M,Z,D)
~~~

## Modified algorithms

The VOPRF protocol from Section {{protocol}} changes to allow specifying
multiple blinded PRF inputs `[ Mi ]` for i in 1...n. P computes the
array `[ Zi]` and replaces DLEQ_Generate with DLEQ_Batched_Generate over
these arrays. Concretely, we modify the following algorithms:

### VerifiableBlind

~~~
Input:

 [ xi ]: An array of m binary strings taken from {0,1}^*.

Output:

 [ ri ]: An array of m random scalars in [1, p - 1].
 [ Mi ]: An array of elements in GG.

Steps:

 1.  groupElems = []
 2.  blinds = []
 3.  for i in [m]:
     1.  ri <-$ GF(p)
     2.  Mi := rH_1(xi)
     3.  blinds.push(ri)
     4.  groupElems.push(Mi)
 4.  Output (blinds, groupElems)
~~~

### VerifiableEvaluate

~~~
Input:

 k:      Evaluator secret key.
 G:      Public fixed generator of group GG.
 Y:      Evaluator public key (= kG).
 [ Mi ]: An array of m elements in GG.

Output:

 [ Zi ]: An array of m elements in GG.
 D:      Batched DLEQ proof object.

Steps:

 1.  outputElems = []
 2.  for i in [m]:
     1. Zi := kMi
     2. outputElems.push(Zi)
 3. D = Batched_DLEQ_Generate(k,G,Y,[ Mi ],outputElems)
 4. Output (outputElems, D)
~~~

### VerifiableUnblind

~~~
Input:

 G:      Public fixed generator of group GG.
 Y:      Evaluator public key (= kG).
 [ Mi ]: An array of m elements in GG.
 [ Zi ]: An array of m elements in GG.
 [ ri ]: An array of m random scalars in [1, p - 1].
 D:      Batched DLEQ proof object.

Output:

 [ Ni ]: An array of n elements in GG.

Steps:

 1. if !Batch_DLEQ_Verify(G,Y,[ Mi ],[ Zi ],D): Output "error"
 2. N = []
 3.  for i in [m]:
     1. Ni := (ri^(-1))Zi
     2. N.push(Ni)
 4. Output N
~~~

### VerifiableFinalize

The description of this algorithm does not change in the batched case.
Instead, the protocol description in {{general-voprf}} changes so that
`VerifiableFinalize` runs once for each of the outputs of
`VerifiableUnblind`.

## Random oracle instantiations for proofs

We can instantiate the random oracle function H_4 using the same hash
function that is used for H_1,H_2,H_3. For H_5, we can also use a
similar instantiation, or we can use a variable-length output generator.
For example, for groups with an order of 256-bit, valid instantiations
include functions such as SHAKE-256 {{SHAKE}} or HKDF-Expand-SHA256
{{RFC5869}}.

~~~
Input:

 [ ri ]: Random scalars in [1, p - 1].
 G: Public fixed generator of group GG.
 Y: Evaluator public key.
 [ Mi ]: Blinded elements of GG.
 [ Zi ]: Server-generated elements in GG.
 D: A batched DLEQ proof object.

Output:

 N: element in GG, or "error".

Steps:

 1. N := (r^(-1))Z
 2. If 1 = DLEQ_Batched_Verify(G,Y,[ Mi ],[ Zi ],D), output N
 3. Output "error"
~~~

# Supported ciphersuites {#ciphersuites}

This section specifies supported VOPRF group and hash function
instantiations. We only provide ciphersuites in the EC setting as these
provide the most efficient way of instantiating the OPRF. Our
instantiation includes considerations for providing the DLEQ proofs that
make the instantiation a VOPRF. Supporting OPRF operations alone can be
allowed by simply dropping the relevant components. For reasons that are
detailed in {{cryptanalysis}}, we only consider ciphersuites that
provide strictly greater than 128 bits of security {{NIST}}.

## OPRF-curve448-HKDF-SHA512-ELL2-RO:

- GG: curve448 {{RFC7748}}
- H_1: curve448-SHA512-ELL2-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-OPRF-curve448-SHA512-ELL2-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512

## OPRF-P384-HKDF-SHA512-SSWU-RO:

- GG: secp384r1 {{SEC2}}
- H_1: P384-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-OPRF-P384-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512

## OPRF-P521-HKDF-SHA512-SSWU-RO:

- GG: secp521r1 {{SEC2}}
- H_1: P521-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-OPRF-P521-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512

## VOPRF-curve448-HKDF-SHA512-ELL2-RO:

- GG: curve448 {{RFC7748}}
- H_1: curve448-SHA512-ELL2-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-VOPRF-curve448-SHA512-ELL2-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512
- H_4: SHA512
- H_5: HKDF-Expand-SHA512

## VOPRF-P384-HKDF-SHA512-SSWU-RO:

- GG: secp384r1 {{SEC2}}
- H_1: P384-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-VOPRF-P384-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512
- H_4: SHA512
- H_5: HKDF-Expand-SHA512

## VOPRF-P521-HKDF-SHA512-SSWU-RO:

- GG: secp521r1 {{SEC2}}
- H_1: P521-SHA512-SSWU-RO {{I-D.irtf-cfrg-hash-to-curve}}
  - hash-to-curve DST: "RFCXXXX-VOPRF-P521-SHA512-SSWU-RO-"
- H_2: HMAC_SHA512 {{RFC2104}}
- H_3: SHA512
- H_4: SHA512
- H_5: HKDF-Expand-SHA512

We remark that the 'hash-to-curve DST' field is necessary for domain
separation of the hash-to-curve functionality.

# Recommended protocol integration

We describe some recommendations and suggestions on the topic of
integrating the (V)OPRF protocol from {{protocol}} into wider protocols.
It should be noted that since {{JKK14}} provides a security proof of the
VPRF construction in the UC security model, then any UC-secure protocol
that uses the OPRF construction as an atomic instantiation will remain
UC-secure.

As a result we recommend that any protocol that wishes to include an
OPRF stage does so by implementing all OPRF evaluation functionality as
a contiguous block of operations during the protocol. This does not
include the OPRF setup phase, which should be run before the entire
protocol interaction. For example, such an instantiation for a wider
protocol W would look like the following.

~~~
    ================================================================
                           OPRF setup phase
    ================================================================

    > ...
    > BEGIN(protocol W)
    > ...
    > PAUSE(protocol W)

    ================================================================
                         OPRF evaluation phase
    ================================================================

    > RESTART(protocol W)
    > ...
    > END(protocol W)
~~~

In other words, no messages from protocol W should take place during the
OPRF protocol instantiation. This DOES NOT preclude the participants in
protocol W from using the outputs of the OPRF evaluation, once the OPRF
protocol is complete. Note that the OPRF protocol can involve batched
evaluations, as well as single evaluations.

## Setup phase

In the VOPRF setting, the server must send Y to the client where Y is a
commitment to the server key k. From this information, the client and
server must agree on a generator G for the group description. It is
important that the generator G of GG is not chosen by the server, and
that it is agreed upon before the protocol starts. In the elliptic curve
setting, we recommend that G is chosen as the standard generator for the
curve.

As we mentioned above, if an implementer wants to embed OPRF evaluation
as part of a wider protocol, then we recommend that this setup phase
should occur before all communication takes place; including all
communication required for the wider protocol. We recommend that any
server implementation only implements one group instantiation at any one
time. This means that the client does not have to pick a specific
instantiation when it sends the first evaluation message.

## Evaluation phase

The evaluation phase of the OPRF results in a client receiving
pseudorandom function evaluations from the server. It is important that
the client is able to link the computation that it performs in the first
step, with the output that it receives from the server. In other words,
the client must store the data (r,M) output by Blind(x). When it
receives Z from the server, it must then use (r,M) as inputs to Blind.

In the batched setting, the client stores multiple values (ri,Mi) and
sends each Mi to the server. Both client and server should preserve this
ordering throughout the evaluation phase so that the client can
successfully finalize the output in the final step.

## Client-specific considerations

### Inputs

The client input to the OPRF evaluation phase is a set of bytes x. These
bytes do not have to be uniformly distributed. However, we should note
that if the bytes are sampled from a predictable distribution, then it
is likely that the server will also be able to predict the client's
input to the OPRF. Therefore the utility of client privacy is reduced
somewhat.

### Output

The client receives y = H_2(DST, x .. N) at the end of the protocol. We
suggest that clients store the pair (x, y) as bytes. This allows the
client to use the the output of the protocol in conjunction with the
input used to create it later.

### Messages

The client message contains a group element and should be encoded as
bytes. In the elliptic curve setting this corresponds to an encoded
curve point. Both compressed and uncompressed point encodings should be
supported by the server. The length of the point encoding should be
enough to determine the encoding of the point.

## Server-specific considerations

### Setup

As mentioned previously, the server should pick a single group
instantiation and advertise this as the only way of evaluating the OPRF.

### Inputs

The server input to the evaluation phase is a key k. This key can be
stored simply as bytes. The key must be protected at all times. If the
server ever suspects that the key has been compromised then it must be
rotated immediately. In addition, the key should be rotated somewhat
frequently for security reasons to reduce the impact of an unknown
compromise. For more information on appropriate key schedules, see
{{key-rotation}}.

Every time the server key is rotated, a new setup phase will have to be
run. The server should publish public key commitments (Y) to a public,
trusted registry to avoid notifying all client's individually. The
registry should be considered tamper-proof from the client perspective
and should retain a history of all edits. We recommend that all
commitments come with an expiry date to enforce rotation policies, and
optionally a signature using a long-term signing key (with public
verification key made available via another public beacon). The
signature is only necessary to prevent active attackers that may be able
to route the client to an untrusted registry.

Below, we recommend the following proposed JSON structure for holding
public commitment data.

~~~
{
  "Y": <bytes_of_commitment>,
  "expiry": <date-of-expiry>,
  "sig": <commitment_signature>
}
~~~

This data should be retrieved and validated by the client when verifying
VOPRF messages from the server. For efficiency reasons, the client may
want to cache the value of "Y" and "expiry". Any commitment that has
expired should not be used by the client.

Each commitment should be versioned according to some obvious
convention. After a key rotation the server should append a new
commitment object with a new version tag.

### Outputs

The server need not not preserve any information during the evaluation
exchange. For efficiency and client-privacy reasons, we recommend that
all data received from the client in the evaluation phase is destroyed
after the server has responded.

### Messages

In the VOPRF setting, when the server sends the response, it needs to
indicate which version of key that it has used. This enables the client
to retrieve the correct commitment from the public registry. We
recommend that the server sends it's response as a JSON object that
specifies separate members for the values Z and D, along with the key
version that is used.

# Security Considerations {#sec}

This section discusses the cryptographic security of our protocol, along
with some suggestions and trade-offs that arise from the implementation
of the implementation of an OPRF.

## Cryptographic security {#cryptanalysis}

We discuss the cryptographic security of the OPRF protocol from
{{protocol}}, relative to the necessary cryptographic assumptions that
need to be made.

### Computational hardness assumptions {#assumptions}

Each assumption states that the problems specified below are
computationally difficult to solve in relation to sp (the security
parameter). In other words, the probability that an adversary has in
solving the problem is bounded by a function negl(sp), where negl(sp) <
1/f(sp) for all polynomial functions f().

Let GG = GG(sp) be a group with prime-order p, and let FFp be the finite
field of order p.

#### Discrete-log (DL) problem {#dl}

Given G, a generator of GG, and H = hG for some h in FFp; output h.

#### Decisional Diffie-Hellman (DDH) problem {#ddh}

Sample a uniformly random bit d in {0,1}. Given (G, aG, bG, C), where:

- G is a generator of GG;
- a,b are elements of FFp;
- if d == 0: C = abG; else: C is sampled uniformly GG(sp).

Output d' == d.

### Protocol security {#protocol-sec}

As aforementioned, our OPRF and VOPRF constructions are based heavily on
the 2HashDH-NIZK construction given in {{JKK14}}, except for
considerations on how we instantiate the NIZK DLEQ proof system. This
means that the cryptographic security of our construction is also based
on the assumption that the One-More Gap DH is computationally difficult
to solve.

The (N,Q)-One-More Gap DH (OMDH) problem asks the following.

~~~
    Given:
    - G, kG, G_1, ... , G_N where G, G1, ... GN are elements od GG;
    - oracle access to an OPRF functionality using the key k;
    - oracle access to DDH solvers.

    Find Q+1 pairs of the form below:

    (G_{j_s}, kG_{j_s})

    where the following conditions hold:
      - s is a number between 1 and Q+1;
      - j_s is a number between 1 and N for each s;
      - Q is the number of allowed queries.
~~~

The original paper {{JKK14}} gives a security proof that the
2HashDH-NIZK construction satisfies the security guarantees of a VOPRF
protocol {{properties}} under the OMDH assumption in the universal
composability (UC) security model. Without the NIZK proof system, the
protocol instantiates an OPRF protocol only. See the paper for further
details.

### Q-strong-DH oracle {#qsdh}

A side-effect of our OPRF design is that it allows instantiation of a
oracle for constructing Q-strong-DH (Q-sDH) samples. The Q-Strong-DH
problem asks the following.

~~~
    Given G1, G2, h*G2, (h^2)*G2, ..., (h^Q)*G2; for G1 and G2
    generators of GG.

    Output ( (1/(k+c))*G1, c ) where c is an element of FFp
~~~

The assumption that this problem is hard was first introduced in
{{BB04}}. Since then, there have been a number of cryptanalytic studies
that have reduced the security of the assumption below that implied by
the group instantiation (for example, {{BG04}} and {{Cheon06}}). In
summary, the attacks reduce the security of the group instantiation by
log_2(Q) bits.

As an example, suppose that a group instantiation is used that provides
128 bits of security. Then an adversary with access to a Q-sDH oracle
and makes Q=2^20 queries can reduce the security of the instantiation by
log_2(2^20) = 20 bits.

Notice that it is easy to instantiate a Q-sDH oracle using the OPRF
functionality that we provide. A client can just submit sequential
queries of the form (G, kG, (k^2)G, ..., (k^(Q-1))G), where each query
is the output of the previous interaction. This means that any client
that submit Q queries to the OPRF can use the aforementioned attacks to
reduce security of the group instantiation by log_2(Q) bits.

Recall that from a malicious client's perspective, the adversary wins if
they can distinguish the OPRF interaction from a protocol that computes
the ideal functionality provided by the PRF.

### Implications for ciphersuite choices

The OPRF instantiations that we recommend in this document are informed
by the cryptanalytic discussion above. In particular, choosing elliptic
curves configurations that describe 128-bit group instantiations would
appear to in fact instantiate an OPRF with 128-log_2(Q) bits of
security.

While it would require an informed and persistent attacker to launch a
highly expensive attack to reduce security to anything much below 100
bits of security, we see this possibility as something that may result
in problems in the future. Therefore, all of our ciphersuites in
{{ciphersuites}} come with a minimum group instantiation corresponding
to 196 bits of security. This would require an adversary to launch a
minimum of Q = 2^(68) queries to reduce security to 128 bits using the
Q-sDH attacks. As a result, it appears prohibitively expensive to launch
credible attacks on these parameters with our current understanding of
the attack surface.

## Hashing to curve

A critical aspect of implementing this protocol using elliptic curve
group instantiations is a method of instantiating the function H1, that
maps inputs to group elements. In the elliptic curve setting, this must
be a deterministic function that maps arbitrary inputs x (as bytes) to
uniformly chosen points in the curve.

In the security proof of the construction H1 is modeled as a random
oracle. This implies that any instantiation of H1 must be pre-image and
collision resistant. In {{ciphersuites}} we give instantiations of this
functionality based on the functions described in
{{I-D.irtf-cfrg-hash-to-curve}}. Consequently, any OPRF implementation
must adhere to the implementation and security considerations discussed
in {{I-D.irtf-cfrg-hash-to-curve}} when instantiating the function H1.

## Timing Leaks

To ensure no information is leaked during protocol execution, all
operations that use secret data MUST be constant time. Operations that
SHOULD be constant time include: H_1() (hashing arbitrary strings to
curves) and DLEQ_Generate(). As mentioned previously,
{{I-D.irtf-cfrg-hash-to-curve}} describes various algorithms for
constant-time implementations of H_1.

## User segregation

The aim of the OPRF functionality is to allow clients receive
pseudorandom function evaluations on their own inputs, without
compromising their own privacy with respect to the server. In many
applications (for example, {{PrivacyPass}}) the client may choose to
reveal their original input, after an invocation of the OPRF protocol,
along with their OPRF output. This can prove to the server that it has
received a valid OPRF output in the past. Since the server does not
reveal learn anything about the OPRF output, it should not be able to
link the client to any previous protocol instantiation.

Consider a malicious server that manages to segregate the user base into
different sets. Then this reduces the effective privacy of all of the
clients involved, since the client above belongs to a smaller set of
users than previously hoped. In general, if the user-base of the OPRF
functionality is quite small, then the obliviousness of clients is
limited. That is, smaller user-bases mean that the server is able to
identify client's with higher certainty.

In summary, an OPRF instantiation effectively comes with an additional
privacy parameter pp. If all clients of the OPRF make one query and then
subsequently reveal their OPRF input afterwards, then the server should
be link the revealed input to a protocol instantiation with probability
1/pp.

Below, we provide a few techniques that could be used to abuse
client-privacy in the OPRF construction by segregating the user-base,
along with some mitigations.

### Linkage patterns

If the server is able to ascertain patterns of usage for some clients --
such as timings associated with usage -- then the effective privacy of
the clients is reduced to the number of users that fit each usage
pattern. Along with early registration patterns, where early adopters
initially have less privacy due to a low number of registered users,
such problems are inherent to any anonymity-preserving system.

### Evaluation on multiple keys {#multiple-keys}

Such an attack consists of the server evaluating the OPRF on multiple
different keys related to the number of clients that use the
functionality. As an extreme, the server could evaluate the OPRF with a
different key for each client. If the client then revealed their hidden
information at a later date then the server would immediately know which
initial request they launched.

The VOPRF variant helps mitigate this attack since each server
evaluation can be bound to a known public key. However, there are still
ways that the VOPRF construction can be abused. In particular:

- If the server successfully provisions a large number of keys that are
  trusted by clients, then the server can divide the user-base by the
  number of keys that are currently in use. As such, clients should only
  trust a small number (2 or 3 ideally) of server keys at any one time.
  Additionally, a tamper-proof audit log system akin to existing work on
  Key Transparency {{keytrans}} could be used to ensure that a server is
  abiding by the key policy. This would force the server to be held
  accountable for their key updates, and thus higher key update
  frequencies can be better managed on the client-side.

- If the server rotates their key frequently, then this may result in
  client's holding out-of-date information from a past interaction. Such
  information can also be used to segregate the user-base based on the
  last time that they accessed the OPRF protocol. Similarly to the
  above, server key rotations must be kept to relatively infrequent
  intervals (such as once per month). This will prevent too many clients
  from being segregated into different groups related to the time that
  they accessed the functionality. There are viable reasons for rotating
  the server key (for protecting against malicious clients) that we
  address more closely in {{key-rotation}}.

Since key provisioning requires careful handling, all public keys should
be accessible from a client-trusted registry with a way of auditing the
history of key updates. We also recommend that public keys have a
corresponding expiry date that clients can use to prevent the server
from using keys that have been provisioned for a long period of time.

## Key rotation {#key-rotation}

Since the server's key is critical to security, the longer it is exposed
by performing (V)OPRF operations on client inputs, the longer it is
possible that the key can be compromised. For instance, if the key is
kept in production for a long period of time, then this may grant the
client the ability to hoard large numbers of tokens. This has negative
impacts for some of the applications that we consider in {{apps}}. As
another example, if the key is kept in circulation for a long period of
time, then it also allows the clients to make enough queries to launch
more powerful variants of the Q-sDH attacks from {{qsdh}}.

To combat attacks of this nature, regular key rotation should be
employed on the server-side. A suitable key-cycle for a key used to
compute (V)OPRF evaluations would be between one week and six months.

As we discussed in {{multiple-keys}}, key rotation cycles that are too
frequent (in the order of days) can lead to large segregation of the
wider user base. As such, the length of the key cycles represent a
trade-off between greater server key security (for shorter cycles), and
better client privacy (for longer cycles). In situations where client
privacy is paramount, longer key cycles should be employed. Otherwise,
shorter key cycles can be managed if the server uses a Key
Transparency-type system {{keytrans}}; this allows clients to publicly
audit their rotations.

# Applications {#apps}

This section describes various applications of the (V)OPRF protocol.

## Privacy Pass

This VOPRF protocol is used by the Privacy Pass system {{PrivacyPass}}
to help Tor users bypass CAPTCHA challenges. Their system works as
follows. Client C connects -- through Tor -- to an edge server E serving
content. Upon receipt, E serves a CAPTCHA to C, who then solves the
CAPTCHA and supplies, in response, n blinded points. E verifies the
CAPTCHA response and, if valid, signs (at most) n blinded points, which
are then returned to C along with a batched DLEQ proof. C stores the
tokens if the batched proof verifies correctly. When C attempts to
connect to E again and is prompted with a CAPTCHA, C uses one of the
unblinded and signed points, or tokens, to derive a shared symmetric key
sk used to MAC the CAPTCHA challenge. C sends the CAPTCHA, MAC, and
token input x to E, who can use x to derive sk and verify the CAPTCHA
MAC. Thus, each token is used at most once by the system.

The Privacy Pass implementation uses the P-256 instantiation of the
VOPRF protocol. For more details, see {{DGSTV18}}.

## Private Password Checker

In this application, let D be a collection of plaintext passwords
obtained by prover P. For each password p in D, P computes
VerifiableEvaluate on H_1(p), where H_1 is as described above, and
stores the result in a separate collection D'. P then publishes D' with
Y, its public key. If a client C wishes to query D' for a password p',
it runs the VOPRF protocol using p as input x to obtain output y. By
construction, y will be the OPRF evaluation of p hashed onto the curve.
C can then search D' for y to determine if there is a match.

Concrete examples of important applications in the password domain
include:

- password-protected storage {{JKK14}}, {{JKKX16}};
- perfectly-hiding password management {{SJKS17}};
- password-protected secret-sharing {{JKKX17}}.

### Parameter Commitments

For some applications, it may be desirable for P to bind tokens to
certain parameters, e.g., protocol versions, ciphersuites, etc. To
accomplish this, P should use a distinct scalar for each parameter
combination. Upon redemption of a token T from V, P can later verify
that T was generated using the scalar associated with the corresponding
parameters.

# Acknowledgements

This document resulted from the work of the Privacy Pass team
{{PrivacyPass}}. The authors would also like to acknowledge the helpful
conversations with Hugo Krawczyk. Eli-Shaoul Khedouri provided
additional review and comments on key consistency.

--- back

# Test Vectors {#testvecs}

Test vectors for verifying VOPRF interoperability. We do not provide
OPRF-specific test vectors as the functionality is a subset of the VOPRF
functionality. Test vectors are also available in the repository
containing the public proof-of-concept implementations:
<https://github.com/alxdavids/voprf-poc/blob/master/test-vectors/voprf-p384-hkdf-sha512-sswu-ro.json>.

## VOPRF-P384-HKDF-SHA512-SSWU-RO

### TV_0

~~~
***********
Inputs ([ xi ])
===========
00,
01,
0100010001000100,
0001000100010001,
0101010101010101,
01000100010001000100010001000100,
00010001000100010001000100010001,
01010101010101010101010101010101
***********
***********
Blinds ([ ri ])
===========
7b,
04d2,
3039,
01e240,
12d687,
bc614e,
075bcd15,
499602d2
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
3f7e2a58d67406e16e75a853509ba20ed92a9f8264efb330df6e4f8f358c905e18c3b
4fa24720f65cac6370cb325d61b086278962625700a35aa64d1d30867e9,
0435394067ac4e46b3f347b9b1561a9ea0356803baaa5ffc2806430caa0dbddbe0cde
1f2c7dd41ac05b18214718ab6a42ceea4ca69a43bd4ab17cd88f2ac6298,
d46b006f9f8c3022ce0822f4c1a71174f006bae4f75ba29c030293a62caab3777f088
06c6dbc38912d2ba91d3f8612cfeb66a0cee354c4b00b44c080ee74de2c,
36306f60798674e64feaa7c24bb16e07c1d565e909d5e8149722043f8cc31d70d8cbd
261822421b4991ed23ab06255c21aa65378c7fb38442267829b0cb1182d,
c167f5828457b9f4e98dd5e34d8e5c0a28e17328b8b0fb605bf54ff72dddd8b46258b
87164312171c0ffce019fca931d9e82036b44b0d5f8fa47d0a9dc27a933,
540fb30045c29d190d740ab1fe5de82a3e88e5fe44348282f84932723df3a4d7dcd10
a019a29802c1eea5aa03b88d9b685cf8a641e1d06e3161b21aed735c5c2,
8e2316b98e6d05b86f6def7702f80d1c780e63952abd8e198ed0d4fd86b71e6cc3e71
a49f89f6606a531b042ca1960dcebbc4e438bd1c31644e7e74b4a0185c7,
0cf8b10800abcea0a0e71f7ad1b316bcd5064c65e24fb470f96312f6491fcceda8f5a
44dbde4f98d87b1bb351655d5d0fa1c87051992bc93f13099cf222fd70c
***********
***********
Evaluated elements (Outputs of VerifiableEval)
===========
0252ed6b793ec4accc5c6a0c1349493916ee39bd1f568b11cdb28ca1a0d9c503c3919
a0b001dcb22b5ed1e46dee0d0438a,
034a3c3b65172e016a3287c582b2c5ad63a3d568107702093a8f32ac34c7c852acee5
907988cd908f97a12a54ba80c17a0,
03634d9098253d145d0781ed8d75c6e6625b5ebbe5c0e230421e4f1b9e5f95ffbbd78
8161c481674ebbb87a294007dafca,
0397e86580377eb897a2ee12348d2066014f1c46b6a6c18a23c1b8084548c4e4c50ec
f21be7d125ebce3b7e6ad4666f8dd,
03b3f44cfa34c1d11016bfa6e5cb97a30ff8c711f170f44ea29df7249d604a9a2b7e7
6aa49b301cf5bfdacabcf7963376a,
023162aa7194a6a8177687c4e5ff6f59176a57376f1586ecb112e90b5355ac02922e5
46add7bc6b94aa0c0ffcd1d7d4de5,
034bc64f7b044d6aefbbf550db774ad972601e198a4954b5383696527fd6f618b6589
75927bb790da448f200976aa7c30f,
02f38b0e9f0e59ca8994028dc3317e4311097c786e815c91673e1935fb71a23d51c9f
00fdadb516accd8ad0860b86af5c5
***********
***********
Proof values (Output of Batch_DLEQ_Generate)
===========
72b3cb082d72b367bbf01272ab7e623b5a6ce38012d76086de01c3cf418398f852edf
eeaba272694eb0bc28811c68c8f,
ccbc3e376e000846413e5f7ff2e395993c18a2d0821d0f9cc93273755e374b70ed1ff
b8caff6e50295f77b0f3b05e4db
***********
~~~

### TV_1

~~~
***********
Inputs ([ xi ])
===========
00,
01,
0100010001000100,
0001000100010001,
0101010101010101,
01000100010001000100010001000100,
00010001000100010001000100010001,
01010101010101010101010101010101
***********
***********
Blinds ([ ri ])
===========
7b,
04d2,
3039,
01e240,
12d687,
bc614e,
075bcd15,
499602d2
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
0cf754250ada1af6d65bc01de944e25862a8b0ce81d79e2bf67f8143356c7126d00d0
84bb384099d436171500080ef314d43bb9e6575b9139c541713a6d7ef34,
8ea771275e7485d9d4c4909c622ff7f108475a693ec042975c5bc7d66667a978f4f03
3cb8541cf2101c77af9278c1c43b2d27fea33fa7989f6201991047345b9,
5a9ca4625ede23631021bbb8540684066dde23b3bb90d4966881fb5358fc666c794e5
4772205227094780701680c16d95355709f45693e1495f1b596431be845,
e98d9a33bb588beec370c593344151fc39c61522bd3476aa51d33fb95949a4718ca65
555436e684886be8336c9b8f4ba6ac39f498dfbd57a123f8ca4d3bcfa40,
e5e4aa81af0b84d747e6b03c9643cb77bcc32f5eea6bc1d5cc9a16b89c85269becc98
06fd438c190c3a0a51666b8293115610dd7c93745c3cb7b0b7023b8a7a9,
553d703e4fdea5a3574c785994c17b29a9f840f1340fa0fa2451483e51f2e6881afbf
de9ecae278f47566254164b489c57d7b8443c5f186f70a4e653c95ab672,
046f558106f4c99b7583c24c8138819d4a483d960ce29c9fea57afe7f07b44d558fa1
a1afe52b0c755f3b6e947cdb69dbce77c06dca6f900ce4b4764cd5d3d7a,
4d17e33e9f654bf106a08b3d5b6bb3b7e2d3b8bc1e486bcd1d6085f33035d6aedd158
7edd8ea27e971f58afe83ee52ab41b4df6c7143820552c111ae014f5297
***********
***********
Evaluated elements (Outputs of VerifiableEval)
===========
020de3169192d97fc8e08a3fa2d988e5cab8abdecff47da139abee98e48644a2434a4
dafd596fd7844bbc91313911cd5e9,
039ddab5a57f8f6a6619a59e59b0b3ac4a1a3ec83c84454a861afb318db482757ecc9
bac179d69269199a280a92e301c68,
033fd8b73095f063547a04f31eaccaa2682d57d9fe8af4218a20f69fc106a016b4a9b
f6cb86a320f0ce1665c95bbd313ad,
0223c17036521d45b62e2b8e42a2cb055367647a19a3a2791534be767ca772780db59
1c8c8e962ef46c0faa5250f47861e,
020a42c5c4449a6c3ce6a797a29e53876ed70acb86bb6a42f77290c82737b0f99edf1
934a4d0cc9b12eb9bd1ab112d6a96,
0277dcd821cbc5b6072fbfcae64faba4da664ed5fd35e354f0daf6efcc289ad3eb7d5
7caf98139bdb2ebf76046d7756caf,
03065ac7a3cea5775e11b4b4774ca5721be77c9ef4e724953f1616fd646faf403603d
b10e191f2bc8b93377b4368a7af89,
032cfc0fd449ddf6e8127eb49ad0e0199abdbb7f9f20e78422bdbd7df48ce4d51bc15
24b2e02d7d372858eb6dfa3535e05
***********
***********
Proof values (Output of Batch_DLEQ_Generate)
===========
fa45e9f9ee55172825d909a3053d98fa37d25ddac1d9f2d31af1580122c3962490554
ed4b8a2d17b158fd0d70310afba,
3af6881c36604f0f3d51d1cda41da28c36275808d83c2c78a3c7f719d667be9a06c80
163f1a5afebc7fe2a7066e8071f
***********
~~~

### TV_2

~~~
***********
Inputs ([ xi ])
===========
00,
01,
0100010001000100,
0001000100010001,
0101010101010101,
01000100010001000100010001000100,
00010001000100010001000100010001,
01010101010101010101010101010101
***********
***********
Blinds ([ ri ])
===========
7b,
04d2,
3039,
01e240,
12d687,
bc614e,
075bcd15,
499602d2
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
44c26cf211201ee7f459d4d53a5fee2e5d7ec3348ba602b1e3ecf2810c8cf39e677fe
287ad14009f7066470a8357051fa4817aa939b76e52fb3b18dc66cf819a,
a330fc41095acd81a8fc834773eded585721f9eafabaeb7d85e95de293c3fbd95cbe7
0627de332b433f1af8219b1d89ea165161a864a9282350271016610c233,
d61836c6a27d6e08cf440c629db10734fc16394bf3da5b3e2fcd4262bd615a43ea494
1c550e942671514c8a1b2d8e5c3dcf773d3a781f11fd1c226f09bf0f1a3,
915bb7d54159e3a925a0ab31d7ab55aaef672528893a38c081a63591b51ed53f35bad
be27b3128a54a69c886b89c8c9aeacf85eff98dda81f6fb77385894d0ab,
21e88f6b54088f2a498dfab512f2c344de54b4a5a5489ba4f0db21a8d1b6a750220e8
ea7808001bfb483af258796b31baf7052694754f785df7d2598b6eb7009,
51211f2ff829b81851567646bdbf7e1c0384906bfce69108edcb8869e99e8f5d3c4f5
3cdae020f67def3c4b3af5d717e1120518e91d33fdf0d79a4582969acd3,
10b292d5e0aef1fe1dbecf39a6dc296129d217df2c2445bea2a40693e2eb883e5c303
76747969d68a66877e07e77385dff634f0b1d8d903cd80d3f7ed2602b64,
828026f2355ea6841dabfeaf73c6b4aa3c773a2b0c3a6434f500b90f69256729bc2a2
4065ac21ac0bed0b552056bd4836731d6112a81c2b3466958c8c4dd7fba
***********
***********
Evaluated elements (Outputs of VerifiableEval)
===========
02300c7e060e1e3ff78eb37f4d6faadefff67c0c15cee9ecd475220d4768e2b858bcb
eddbf3cd9f8fbba992617a549cc86,
024b9e6bc2d41d3feb146f3c9097ee4552fdd2cd31e7c85f4536c69809160c883a3f1
7a85fd1e875f0d4b2c8be4e1ee6e9,
0385f70b3e08f70434f0b21e804082581fbd6872af51d7e60967b0a28889c20a32386
7e635930e526cb5ba0961b79f6bcd,
03ca1fac4f9d5817e47dc32dbe0409dbeddf3da1bb0825bba91d80f9733dd3af46fe7
17de1ec0092da23f287834d657e01,
02844cabc58c06502d405bf7a25fb77aa6238e054817a25ce8d4de061ae8788f1a213
d4ea7bae7eca32fb9fb08c183ac73,
03afab35b49c2936b5627051042026f110cdc8f10677c433872da2a8fac33da57698d
8a089b59c959bbd2981042a4d7c57,
0325410ebe07f468cfbfc7beaab84154b027cdc9c82d16f44771a667425a7a911b7aa
d3620d45b92bd69508ec1634f6cfa,
02b50a35d6bec54b09930ea81e74ced355fd87143a65527bc9fa570a8869b3372f4b5
952b183df0c0f8bb421c6c366bae9
***********
***********
Proof values (Output of Batch_DLEQ_Generate)
===========
688fab70c0b4d0d276f977188ff4c9d8d3e18509b772588e8c63a368a6585b4ad5683
462515b90c430412b36bb019ebe,
12d9787fe36bf8e1319d1b65a0afc7721b869d124cdb30c4e81049011bdca02ff4e9c
0d58f45e5de9d5a37571517e50a
***********
~~~

### TV_3

~~~
***********
Inputs
===========
0100010001000100
***********
***********
Blinds
===========
499602d2
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
dc4904d034a446b970ca78c91ca2ffa944ab2fb9f22f998302b564b2d18059178bbdb
f450e17aed37549c4e11151414cd908cf4740d53a141af027eed3b17bb4
***********
***********
Evaluated elements (Outputs of VerifiableEval)
===========
0292b735c386df2ad67322cafd8c28f79321c5f39ac2ca6ad1f4eff699ce13f88ea0d
935dfb74438dfe64a2feebfcaa1e1
***********
***********
Proof values (Output of DLEQ_Generate)
===========
eaf71b3a1253b092fe430016c5a4352cbbe3844c8efea14ef52f22b0b70c2faa907b4
fc08a76de7d02a89686cb9df0a6,
3887e2ae5ed546512eda769d5313df7121584d0955551477b7d7f7351303fd2d5e298
dc13f7f65271e3c762dc45295c1
***********
~~~

### TV_4

~~~
***********
Inputs
===========
01000100010001000100010001000100
***********
***********
Blinds
===========
075bcd15
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
36ea8a2d34e37cb1b33e75266fdf73efd316c7103c66ba8b15fde1565c84d20fc4f78
705315c1af14c0b1b548a939839a3d78e802789e9031a01a2ee3b386a38
***********
***********
Evaluated elements (Outputs of VerifiableEval)
===========
028826054c0e2a27181343dc9f8914e4b1db497f499dfe008591d25e84440be928549
fb3dabd6ba69d73f08643a1fa95b9
***********
***********
Proof values (Output of DLEQ_Generate)
===========
45001dc1ba6a729ef68db78706dd4d9bfbfc7877f125a4963ac0bee04e96527c5edde
e46fd91259f34f396c0c75ce76a,
b738431867c9873da1d4c4c68f3f94d5637a22a924766e0a96905f56c3af238320111
3f95f94d43a5a20ae5d73b01048
***********
~~~

### TV_5

~~~
***********
Inputs
===========
00
***********
***********
Blinds
===========
bc614e
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
77fa8ae9b11d3e81b9206233402d1e170ac1671f4920ca775fb2b3c42e98150c3c80c
a739055b5bab2448d8ff3234c486f60208d8cbdc826c32667c2f2fab942
***********
***********
Evaluated elements (Outputs of VerifiableEval)
===========
03807b46cef133ff1354d7d03bc02a6dc6950e6753552e4cf6d73eb221d1d2c7d25bd
39b8bbef730913ea02d98580757b9
***********
***********
Proof values (Output of DLEQ_Generate)
===========
980fc8ebb47afbce5b6e0d180d880c4c55051cded3fde5f5e6a1849cb78076e9606f2
6a4847f07afc69db7fb0c758fd7,
81b2c1fb3b9f0608e80103e7d21519a83e048c6d26bb328605e09c134d4ec98160f16
64229d26003571534c94c6aad99
***********
~~~

### TV_6

~~~
***********
Inputs
===========
0100010001000100
***********
***********
Blinds
===========
499602d2
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
f112516ddc6f9f938036b695e78946ce6b6983d211e9f4263311fe4d454f64ed5b7ae
e89d459acaa8bc9392e27c63f2389f83f0b7a09fa36d0e20c89be5a28fd
***********
***********
Evaluated elements (Outputs of VerifiableEval)
===========
022dd65bf069048a5a44ce8dd27a6f8f3204f756aa444e09a6b880d99fef8e182df60
ebac9e757c5d93cf13283c959c9f1
***********
***********
Proof values (Output of DLEQ_Generate)
===========
acd48f19b025e6ee0c84c4af3f2df6f041a17117a41d7f151f2986de03ddf45d5758a
d26e826d1f33be7431b7ad35954,
7161010c5f67f27a9294d922a9ec24f17563d650f5ec1523fe2c420676a44eb837c91
f87c562bc472a7259c47e7a6547
***********
~~~

### TV_7

~~~
***********
Inputs
===========
01000100010001000100010001000100
***********
***********
Blinds
===========
075bcd15
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
681414ee7f1707751e6c930ed8dab48d847d7633a976f0f03397b37831d013ed1059b
130d2c36f1104577e7c0e60345980367df5bf31bcf27e2559bf58926df7
***********
***********
Evaluated elements (Outputs of VerifiableEval)
===========
028476abd0cd2253c0a109e57aeddb5bbc5cac56d67f94c3062dcc9b487d6bd5d23fb
84f62ab093f9ec6cfbd9e75d48160
***********
***********
Proof values (Output of DLEQ_Generate)
===========
a3ae64e742a2eba25823aaeae02cb89805ff2347ed4ae7fc6ee5ce44cbf4c3eff0591
04d90b7b7b2aab32d48f59da882,
6a5117e4ec2c2a7744833845c06f545f6deb93e1451906ba049b56a582be6a003d447
bdc431d49d5766075d8c065a58d
***********
~~~

### TV_8

~~~
***********
Inputs
===========
00
***********
***********
Blinds
===========
bc614e
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
1a999cad56ee7667dc9eb8ef0ae9438264e3eebc10b4dc06bf5fe7ab11399fe241f85
f0199b4bd6936a6410abeed5286ae92ee07020aa3fa13c97185d5687c0f
***********
***********
Evaluated elements (Outputs of VerifiableEval)
===========
036c2599c2a4ccc79efe7d7b25ef2ca6281c20798aa5216d74488363fe85bb7c9971e
88b81cadf1e7a209b2264a71c8b3c
***********
***********
Proof values (Output of DLEQ_Generate)
===========
ea113132ca3a3e874aa01ae4c39fc34da8ae45a28cde04d0d29056d178d0d0357b743
dde6524529c99d9d44d11ced40e,
46037e772abfcde45da3b2f42ed1272d375a667bbb996aeee8bd6c83967b4fe4b8e99
d791e0570d41f57e79bc0c5931a
***********
~~~

## VOPRF-P521-HKDF-SHA512-SSWU-RO

### TV_0

~~~
***********
Inputs ([ xi ])
===========
00,
01,
0100010001000100,
0001000100010001,
0101010101010101,
01000100010001000100010001000100,
00010001000100010001000100010001,
01010101010101010101010101010101
***********
***********
Blinds ([ ri ])
===========
7b,
04d2,
3039,
01e240,
12d687,
bc614e,
075bcd15,
499602d2
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
311504d9f3a8552d79ec118d81535a2e1f506a661a7bde24e7829d9af2f2a6bf15e24
62e7a82796d80eed656ed39618eb89e88f659efe3d90430adf4cb8d0d5b,
e46726e653134b45a2cec057006c826becc0345c34e0388433ea27dbaec9c40f849c9
d37a50a7c7cc95bc231b64420994099681ebdf11c6db29ec30decc44bdc,
e3693f7dd36a5479a3d7478106aceac21be6f35701490d287fed46eb013db8e8e5eb0
d8fd7edcb3e0fd8baa0aa15af980e658c99ad8c73e1204765c54880e768,
e9706bcfb488e163472747d41573060c5cdfe5a5c0df69b4b68d02e02ba1bbc63f39c
176cdcac6762ed0c0f6081cee333e60fd095d5233ee780f7fd72a78afe7,
083425c700814171e5b474901f4ed8db31b797ff1285e1400c64bc2fcee33fa20e335
28c230bc2afbf324285ae809ef60508ccc519c4fd2cd4583b16cbd86745,
6895c0e37410b7edac495be5031b9674c1853512bcb3fe87e40b7fae125eaa8a144c1
eb2f73117de87b3e84923580192ce80c1766ad1027133748740d0ec4307,
df791c2c37aba786162e35820fb8f47d73b42fd282ac8aeb16f3abc16e80df9200cd6
d1e43b45aa5bb12b5bcaff073eb314b22e6ddc63bff3f91e7cf658c83fb,
011c0dce19513a182a7659ff513e97b368d6f088d772e86369b59cc57a1a87a422bbc
d3fa54924576f90532a29bbf5fe7afeb7b7b56a247a88ae902c0f2bb997
***********
***********
Evaluated Elements
===========
0201d03b51cd85fdf33296652cd8e68b8cf52483d871e22a9d5e96bbccbabe09522c3
52ef524ed4043335b824ff14de8decc5df100e769ef9fac62513b1df3ed10c249,"
0300c4d2aabdbe9feaced304ee45e0affb5c4f21876c74f109cd042c7118a8f480194
d324393260ee8d357fe98f1d9d19e86a2c0637ff3a60c23692b30785da76f9c77,"
020181e87b02e3b562e35b2ea3ad3616fcdafbab1cd085cd3e7f6e6110923bbd5e3a3
e12f5551caeb1ee39f1d059eb380b6a864f24ff8a2fd6297f7faa6cee2e762fba,"
0300b8bbaf3fb114aa986cf5fdaa083c6fdab78379ad2b6e48cef0d146af902350ace
c87b47ba62771d0b80efb32bb48b230916df2cc345f23980937e90bc69ba1193e,"
0301718b3d92d1abf787cb65508444f0990155aa71c919e937b8304a11ce59478d51b
73abbe727c892901b6b8015f204d30c50144a45cdb0dd06de56992a8ba08e0ec2,"
0301c2f2bafea55c8cf0fe95b426934426728fd491a7b8efc8199a67a8b97f0e71e62
063185fcd51b0ac49191a525160561d62162b65e16670c45e9a8e4a31a26cd051,"
020027c309c68d22f87cce7c4f6f7f0f68bdafc01ee03a1dedbef80f4f96da544c563
487601308455f83dbf6f65914767b00084b3a5d216344144aa79d9eb84e0ad985,"
03013a21128f0b7e164cb372ecfc01d2db0c63a7ab1041976f57bb1cb1998221b3846
3aec15cd0ad8676b0afd01df4c545da8ed65377b6dae6533e1dd59d10190688a1
***********
Proof values
===========
01bfe207273b1de738efebd868fad83d7dfb09368d437ae7f4066b291defcff362daf
3b06a38fcb47f59e83053fc60f54dac663dadb5b70e169a6f5b3d1fd670bf89,
011fa190d6bfd0bdded89bf20f5422cbb32b6eedb0c9ce21325ee97e372a00ba5598a
83b9db20da88cc0f23fa227e958ab5abb281d6357631ea1ba499fe1475bebf4
***********
~~~

### TV_1

~~~
***********
Inputs ([ xi ])
===========
00,
01,
0100010001000100,
0001000100010001,
0101010101010101,
01000100010001000100010001000100,
00010001000100010001000100010001,
01010101010101010101010101010101
***********
***********
Blinds ([ ri ])
===========
7b,
04d2,
3039,
01e240,
12d687,
bc614e,
075bcd15,
499602d2
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
22c883405baf28fe4d59fa9b69e967362a7275183f14820c178530830d6dcaa6e281c
87e297419f0e376c32b0b5355add9df274076fb6d2a2d842092bcd7d0e8,
cd2b0dc2de6b5f978cfcab81f8ee415debc09fa2e40af0497fc969118901f01888956
ff7112a201769a0522443ffdfbb0d960c215cd8c1bcaea003ef2a82b38e,
3c203790f5938294610fb068dd9a2b9408a2fd374b1104fbe026f205579a6af7e339f
4dc0d01e3e1f3d3d3394e23089c1fc4b88d0538f2d94df054e8e8a7cea9,
e0fb6cc3a0883b81e4d0c3c0b6f065bcf5aec98c1a4ea3df7f5ae6d3b6b0564999967
84b4262d4a24545e2de9cff95abe852dfb0134d2bb8814a6f5f3d684d74,
976bfda758c6563e66ef74cc437e93f8718b13d92682ecebf5c20ae3aa1a1b8a4d5e2
e8e51a40add43e143079e20dc6e405f3b0d3ac909b4c269987904d53fea,
f5f8d324e4d1f8d84f9e0f65782d59510e2645a378e4fdf8645351502f17c37b3e2f8
59f229226b441ed21cabf3eae98e913264a568f82974169a662bcdf5c31,
7c325eae55f94ebc72f50e393c0b396ca4bf364ecaa53ffae468ace08bc23a144ce2b
fc26b18d38d1dcc198a9a3969c7277f2550989f135284ddda156c22cb9c,
9049f64811bfc62066eaa86b6c55c419f590cc85ef8295409610f7f3b4e20e0ef255b
58a6a239ac770d8b32c69cccd8616cac4f5bdfbb2b2dcacc98bb83996ed
***********
***********
Evaluated Elements
===========
020129f4f00938afcf0a82b49c5352db53bfe9d9653a99e7506e95c57d1f6441b166e
102ea083733b6904520884f4ab0b5f30fc046d939803697a194ba5ca9e496a6c4,
020155994a6dc28b99f37933a08feb496e69ce9ed8e2585fac29f8745af33927696d9
9273faa4a8f98e25fb3a0238f069bfce936ca7919393e19721bacc26638af433a,
030094eb2c29bb437f3f23dbe593ea0d3d1a89423985bc0655834aec17fa9b9f395bc
a6220854cb3476a87bdab716ea7d88c81daa666f480e5268f19bb115089e901c9,
02018fbfd7cb304c98466cca51009eed2ea566bdfc23bd8195fcb41fed4267682522a
b06566f401b53ac4a5082431e103ed1d84ea79610713fa2ff71cb5714f5e8ac56,
0200d9d75b83194c6e9bfdb61d47ce5c06330ab2ba9ee491c048f9529ce0e46c395ad
c5589eb41d256af9723663c2a8db6912ce172f2ed42475e539fa94da8c15d6a87,
02008941a06a90e7004754fb43ac273f85bf488bfb29122ef634689ccc5eab690b96f
12b355b6401ac92bc386403a8f28f69126148214003c90281418551a2d71271fc,
030107a4863b08821ce1e29b6ea61af72a14d827c4a9c4f60f49db94803b75f56e8a3
9f0357e8fb5acc22c4d8b923fecfb3aa877a62f3a6b860bfa251bb19e3be7c96e,
0201aff79ccaba2fba1765fdd36842a941bf2f46d3aad38d99703820eb44214aec464
f284883a81bd10aaae312fbecc195ddfc006c527db0c59688cac26d33d19abc4d
***********
Proof values
===========
7f5afdbf8bd3d3d619118a3b010778e04bb20b5aa4dabe20c68ec96a72b1d4525e593
76345c1c9b1980e4ab2feea41f86e01a90a6db0eee871bdd72a5d4e941336,
f7219034d5e5064a8de8e1aa29f1a1f1a775587810915ad624a74a1c75fa0ce78e9eb
b2fb0cb183b7d9e35e76ba2019e9d592ff8f90ee454e64a230e4ed3571a93
***********
~~~

### TV_2

~~~
***********
Inputs ([ xi ])
===========
00,
01,
0100010001000100,
0001000100010001,
0101010101010101,
01000100010001000100010001000100,
00010001000100010001000100010001,
01010101010101010101010101010101
***********
***********
Blinds ([ ri ])
===========
7b,
04d2,
3039,
01e240,
12d687,
bc614e,
075bcd15,
499602d2
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
ab54e7e884a6bce888f83582da3ad7452c8ce1fdbee479fd68467034d195a31c3ee44
25ec9502be736457c99e7ad0a2f37dc54075a984ea50b6c9fae3ac04715,
8aa9817109249699ff28a06165d415880af181497ee51c86443481efce512252859a1
f17a80a4166dc1471db4fb1a90d818b46dc39f621fd53cff4aad45c821e,
7473c6fa86029c8dad90b6658866ebeb507f4f58012c27fd81db245fefdd81a6ec76a
c92c2fde4375a349cb5cd84b2218b25232b2d497d14caa10c8643ebaa27,
daec44675ddc03a3ad45b72952b3ffecf5f29b3f6b4bbe1c759ec27e1e751bcac4286
e125e6bb50a81c189c7c6039c6d5021fe09502a5a48fb61e8e6eed438a1,
61bc70931aa556e053c39f6283381a160c35f4053d52ec12b243197540ba603156b90
fc06a5b3d3cb7f3dae6a2c1a7e0c4fa380581e270d717fc4ad4220c4d54,
f0299158c5b23c36954b783192819e2f17dabc772c117246abbdc1abcf61a2f30f23d
6f9277dbddba64254b309b516e4ee5ad795ad0463493b71b38a5faf5699,
6c84becb606403ae77c4d73a4f86f5a8a0b0a78d38e84a298be77d6d93c5a853a3b69
2c22fb833604dd5d52ac32ec8e68430c9a51b530bc8a88175b24a303d4d,
48f39980174280894454a2dbb48a9fe1982f7fa9b3cf8cafc45a8e762a8224892300d
308a1295ddca35959993f9a95c3059c1816483ec591dd82cffe5ead1e57
***********
***********
Evaluated Elements
===========
020039802019cbe676c04e7bb45d3d8046c20f8b56b43157f8f14fc14bf42acc57d24
717ebaedf3ae4130009daa6d8f8dc3a54f3e6273f71acc4d2e0a2b12cc96ec51a,
03017fe9835bd80730bc63a30436c356b1d2d9d9b0c5e15638af82996bb4ce17645ea
95aa6d9df02b3d3dadfc6ad29283f1bd23dde064aa711ebe96561e9c0044350ef,
03011d4af3b787f338a595cd5d8d89dc0d3c8cf09f9f6dbb3ff0472b0af5a87d951e5
01d2b3b5643b89b27ea99ffe59ed340b1d60a362b3be9c505fa825111824fa9de,
0301f10643c873d09dbee17daab65b1812de557547acd0b8f6c3d9d43abbd19b9dad9
01f31ed6436e809f0d4f91d04d1f12c60413c478e2a55a6f829b72007430eb11b,
03018d39842b5357e3a46dbfd8379dae686aed7fdb4755511e3843318efee9255c606
e43fd4bdae0278025f0ea941769833c2f71a2b89deb54696699714258d7e995c8,
0301b05fb7aac399bd48f45f759330c8072646d0afeefcd427c71b4ae7d5124c57b70
5e655e655da3111f561e4d6911e005d2b2ca5439ae995d8ed0c8c376596b044bb,
02006b8ef1c6794dcae3f0f58fe18e05335267a48366b433e6d47898578151ab52c2f
d40e4d338c422f56e3b01ddb9b43e5df948e722d675ec1a671d457e8145fcbd3a,
0300c269713af6a6d73bdcaf35e6bf46d4cc09e94c338649da56988241bf2a06c12ad
ab5d2d801313b03c273026dcf8b85ee30e0b0dbf40946d7c94fa2395271bc3e13
***********
Proof values
===========
015b663c97018b58713915546637cb56cee3fe66df41755116ee3b4eb51f122d27ba6
e9c183cbfcc9349f7a2a6ad5a39553b2cc3b68cc05143c021c2f05c88f748,
694c5ec10016faf4a579ccb63578a2000e840f61741fb1be4435598570ed73ab278ed
edbc6c15e51eff7680fcc6849f6073d88786785f15634ac023f5615749e20
***********
~~~

### TV_3

~~~
***********
Inputs
===========
0100010001000100
***********
***********
Blinds
===========
499602d2
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
6de5cf4bdd071467f40ac4705f927e33935df9fa4dfcded632c8b0c1f4551b541a2c7
c31091ca7e9c95ab69c3a99df7344197c431949d567dd6e0a092f4d8bca
***********
***********
Evaluated Elements
===========
020119c888270bdda028963448ac29d754e565a6e9afe3ae1a1d56969cad2ce51c753
fb5bf7e0f0c9a74af5c347e0f1134028751ee9101e20b74e6ad2e52b3fd5070e8
***********
Proof values
===========
"afa2e74f82f7305dd312c1f75a5a41e57f6c5f0c48234867b7bfccc5957c68e17242
aef97cc3c84063fef2b72ecf477a9de1ed69a04197e02537425970566db30e",
"01f88beb10e6724a926bd3cf6715c30ab0f27f092d88a8bc2f0d24163bbb4dec256d
f44882771b36b2168d8df327812f377f3e5f5d942907e48516fb1d267befca0d",
**********
~~~

### TV_4

~~~
***********
Inputs
===========
01000100010001000100010001000100
***********
***********
Blinds
===========
075bcd15
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
438ff35831f87c05f2702fd26130a872f6feaa0f161daa0e5402ff32ad12cb930898c
fbcf7254265a4f318b38e3fb54044fa39aa6dba7b9b7dbf8bb1d3718513
***********
***********
Evaluated Elements
===========
0201c4f3d1fdcdfa33e0dbdf186b133daae446aecd845ee47a3a51d9c14a5c124e04b
da8ad4f1fabc57109bfd17399fa5c359db1cbc35f863395ca6983046dc5d32cb8
***********
Proof values
===========
019bc2c98e379fd9b203194363074be0e621e0b0c1119944a48e26a24f6054632404b
48c58a8b9ccd4e3956b22f59d21e282b21600de9e2581a4046c05aee233c826,
01e15d541841aaf7244228be444e91e7db4f440e9ef0bc5da0fcb24681989794710a3
bee04b6e0b661ae64919beb68a2859f387e33e0f6d65599ecce5095e3717439
***********
~~~

### TV_5

~~~
***********
Inputs
===========
00
***********
***********
Blinds
===========
bc614e
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
aaadc31e4621df9a79e63cfcc284c989f0cd115806b3b992c7a1b8e17ce6e90d1767b
db39e355f198d9bc08dfdc802b61d3ef6d5ff6f12f66cda33ddaf52038b
***********
***********
Evaluated Elements
===========
03012690f64d8938455183639874c764d8bf3755ea097694610c65531e2b15fb1dd4c
a41ac264b08744fc9756c773bd8684f94f717ea3f387199aa6add402979e13f9d
***********
Proof values
===========
013d1ef2ec9b8a9d57f25a2c0eceaeabc413cdda6209e8daa5d57d3f3efadf25b49a8
2bdc2227ae8783b91a6a802ba764c05eb41cc0bf2636240ce38daa6df4ff4,
82158f49fdf7de079edd93e0b1dc1c6f854ec721a229f3120eaa6a9f77a74cde42b72
e5acfecb64ea5798ec02e7091325c156aaadc5914dc9ce133920a718b02b9
***********
~~~

### TV_6

~~~
***********
Inputs
===========
0100010001000100
***********
***********
Blinds
===========
499602d2
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
2d4ed44164545f338ef9c8559a8b22c851fca99a29c247a02a4c3cf365d9168d9e883
7a459862cbbc9d0840fe6ebeac06a19425551324c2852cd3e34f215b31a
***********
***********
Evaluated Elements
===========
020034a45b808ae28d020f9337ca39ac7dc02db95a8d7f17296c9bb07905e1ec41e43
240e84a64fdae0e7d7b018dd945fa88443bfaf6f6325c645b16929339eb4ee142
***********
Proof values
===========
0199142b4549d6cc38dbe891aaf99918ff70397a53d8fb6fe5625f6c22ebc03f852fb
63125927ace5f8c84e0c458ee220d337db428894499b4375577a2d861e33019,
011e3741e0af9ea507aae87b81dc82e1fc132117bbf9b6f3874af1ef1edc8b861bb39
97595151939b41d6f44d01afead55d72b921ead725b2300dc4bbdd3e35132da
***********
~~~

### TV_7

~~~
***********
Inputs
===========
01000100010001000100010001000100
***********
***********
Blinds
===========
075bcd15
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
347304a781ffd6a71e68220b2207075a1214b265e9b05a9e7298637f4160668f9b358
49ddbbc33c479ab9b29bff721ca783f2df7ec4e9a9fddef60de256aa4ef
***********
***********
Evaluated Elements
===========
02018f172d191622eaf6df4e67af22216ab3a7ba2725364c00c0c5bf78d79befb9570
17cb335becf55c08830d88de0664f6e1e4720b8b00fe435ea8b8c2c229dfbd2a0
***********
Proof values
===========
8b5ac1ce7166390864432474f7847c7745d008064a7fc1ea704593ce5c5fdc323da77
c3832c4170e518234521889022ab6385555aa1728b7d35e62926c466e6833,
01557b99c93d672ed3d04c5f16ce2e174ca7ae010015ee3444562dfe1d12ba78cc2c9
360accebcd667b4b5d49cddf316322efc24b0c287ecd983de24a5b0bc24adf1,
**********
~~~

### TV_8

~~~
***********
Inputs
===========
00
***********
***********
Blinds
===========
bc614e
***********
***********
Outputs (Outputs of VerifiableFinalize)
===========
2da05e2a2d9a8154f259ab195873a7e48016dcf81d62d7af587bed480602597f841b1
b5e87d42a39b01cc6dcfca9d5f06e7a822b341381caf1dc1c0e5478cf14
***********
***********
Evaluated Elements
===========
0301b33b1616997515b072438e3c3bee7662bb949bad7c27fc151c0dfc527d0e5eed0
41f95e626ca9c6cdb71f7d8ee44be891d480ece6fbafdbce8a8e1112c37a3889c
***********
Proof values
===========
01ec45955ccbba7e752c31fbc23438a4fe4f51c4cf92fb7cb5774b27ce808c0809bf6
fbc029f9a92afc9b7a168350e165b8b28bdc28e913a2bfc159c44f0a6867421,
016b2052b232342911ffd541417aca4ab6eae2c82081d565efa07057d96ef400c686a
3366673b7ad22bcc0752fd085eb354cc893e91c3427ccc7dcf6f1e1112bc790
***********
~~~
