---
title: Oblivious Pseudorandom Functions (OPRFs) in Prime-Order Groups
abbrev: VOPRFs
docname: draft-sullivan-cfrg-voprf-latest
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
    org: ISG, Royal Holloway, University of London
    street: Egham Hill
    city: Twickenham, TW20 0EX
    country: United Kingdom
    email: alex.davidson.2014@rhul.ac.uk
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
  RFC2119:
  RFC7748:
  RFC8032:
  I-D.irtf-cfrg-hash-to-curve:
  NIST:
    title: Keylength - NIST Report on Cryptographic Key Length and Cryptoperiod (2016)
    target: https://www.keylength.com/en/4/
  PrivacyPass:
    title: Privacy Pass
    target: https://github.com/privacypass/challenge-bypass-server
  ChaumPedersen:
    title: Wallet Databases with Observers
    target: https://chaum.com/publications/Wallet_Databases.pdf
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
    authors:
      -
        ins: D. Chaum
        org: University of California, Santa Barbara, USA
  JKKX16:
    title: Highly-Efficient and Composable Password-Protected Secret Sharing (Or, How to Protect Your Bitcoin Wallet Online)
    target: https://eprint.iacr.org/2016/144
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
    target: https://eprint.iacr.org/2014/650.pdf
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
    target: http://webee.technion.ac.il/%7Ehugo/sphinx.pdf
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
    target: https://tools.ietf.org/html/draft-hdevalence-cfrg-ristretto-00
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
    authors:
      -
        ins: M. Hamburg
        org: Rambus Cryptography Research
  OPAQUE:
    title: The OPAQUE Asymmetric PAKE Protocol
    target: https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00
    authors:
      -
        ins: H. Krawczyk
        org: IBM Research

--- abstract

An Oblivious Pseudorandom Function (OPRF) is a two-party protocol for computing
the output of a PRF. One party (the server) holds the PRF secret key, and the
other (the client) holds the PRF input. The 'obliviousness' property ensures
that the server does not learn anything about the client's input during the
evaluation. The client should also not learn anything about the server's secret
PRF key. Optionally, OPRFs can also satisfy a notion 'verifiability' (VOPRF). In
this setting, the client can verify that the server's output is indeed the
result of evaluating the underlying PRF with just a public key. This document
specifies OPRF and VOPRF constructions instantiated within prime-order groups,
including elliptic curves.

--- middle

# Introduction

A pseudorandom function (PRF) F(k, x) is an efficiently computable function with
secret key k on input x. Roughly, F is pseudorandom if the output y = F(k, x) is
indistinguishable from uniformly sampling any element in F's range for random
choice of k. An oblivious PRF (OPRF) is a two-party protocol between a prover P
and verifier V where P holds a PRF key k and V holds some input x. The protocol
allows both parties to cooperate in computing F(k, x) with P's secret key k and
V's input x such that: V learns F(k, x) without learning anything about k; and P
does not learn anything about x. A Verifiable OPRF (VOPRF) is an OPRF wherein P
can prove to V that F(k, x) was computed using key k, which is bound to a
trusted public key Y = kG. Informally, this is done by presenting a
non-interactive zero-knowledge (NIZK) proof of equality between (G, Y) and (Z,
M), where Z = kM for some point M.

OPRFs have been shown to be useful for constructing: password-protected secret
sharing schemes {{JKK14}}; privacy-preserving password stores {{SJKS17}}; and
password-authenticated key exchange or PAKE {{OPAQUE}}. VOPRFs are useful for
producing tokens that are verifiable by V. This may be needed, for example, if V
wants assurance that P did not use a unique key in its computation, i.e., if V
wants key consistency from P. This property is necessary in some applications,
e.g., the Privacy Pass protocol {{PrivacyPass}}, wherein this VOPRF is used to
generate one-time authentication tokens to bypass CAPTCHA challenges. VOPRFs
have also been used for password-protected secret sharing schemes e.g.
{{JKKX16}}.

This document introduces an OPRF protocol built in prime-order groups, applying
to finite fields of prime-order and also elliptic curve (EC) settings. The
protocol has the option of being extended to a VOPRF with the addition of a NIZK
proof for proving discrete log equality relations. This proof demonstrates
correctness of the computation using a known public key that serves as a
commitment to the server's secret key. In the EC setting, we will refer to the
protocol as ECOPRF (or ECVOPRF if verifiability is concerned). The document
describes the protocol, its security properties, and provides preliminary test
vectors for experimentation. The rest of the document is structured as follows:

- Section {{background}}: Describe background, related work, and use cases of
  OPRF/VOPRF protocols.
- Section {{properties}}: Discuss security properties of OPRFs/VOPRFs.
- Section {{protocol}}: Specify an authentication protocol from OPRF
  functionality, based in prime-order groups (with an optional verifiable mode).
  Algorithms are stated formally for OPRFs in {{oprf}} and for VOPRFs in
  {{voprf}}.
- Section {{dleq}}: Specify the NIZK discrete logarithm equality (DLEQ)
  construction used for constructing the VOPRF protocol.
- Section {{batch}}: Specifies how the DLEQ proof mechanism can be batched for
  multiple VOPRF invocations, and how this changes the protocol execution.
- Section {{ecinstantiation}}: Considers explicit instantiations of the protocol
  in the elliptic curve setting.
- Section {{sec}}: Discusses the security considerations for the OPRF and VOPRF
  protocol.
- Section {{apps}}: Discusses some existing applications of OPRF and VOPRF
  protocols.
- Section {{testvecs}}: Specifies test vectors for implementations in the
  elliptic curve setting.

## Terminology {#terminology}

The following terms are used throughout this document.

- PRF: Pseudorandom Function.
- OPRF: Oblivious PRF.
- VOPRF: Verifiable Oblivious Pseudorandom Function.
- ECVOPRF: A VOPRF built on Elliptic Curves.
- Verifier (V): Protocol initiator when computing F(k, x).
- Prover (P): Holder of secret key k.
- NIZK: Non-interactive zero knowledge.
- DLEQ: Discrete Logarithm Equality.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in {{RFC2119}}.

# Background {#background}

OPRFs are functionally related to RSA-based blind signature schemes, e.g.,
{{ChaumBlindSignature}}. Briefly, a blind signature scheme works as follows. Let
m be a message to be signed by a server. It is assumed to be a member of the RSA
group. Also, let N be the RSA modulus, and e and d be the public and private
keys, respectively. A prover P and verifier V engage in the following protocol
given input m.

1. V generates a random blinding element r from the RSA group, and compute m' =
   m^r (mod N). Send m' to the P.
2. P uses m' to compute s' = (m')^d (mod N), and sends s' to the V.
3. V removes the blinding factor r to obtain the original signature as s =
   (s')^(r^-1) (mod N).

By the properties of RSA, s is clearly a valid signature for m. OPRF protocols
can be used to provide a symmetric equivalent to blind signatures. Essentially
the client learns y = PRF(k,x) for some input x of their choice, from a server that
holds k. Since the security of an OPRF means that x is hidden in the
interaction, then the client can later reveal x to the server along with y.

The server can verify that y is computed correctly by recomputing the PRF
on x using k. In doing so, the client provides knowledge of a 'signature'
y for their value x. However, the verification procedure is symmetric
since it requires knowledge of k. This is discussed more in the following
section.

# Security Properties {#properties}

The security properties of an OPRF protocol with functionality y = F(k, x)
include those of a standard PRF. Specifically:

- Given value x, it is infeasible to compute y = F(k, x) without knowledge of k.
- The output distribution of y = F(k, x) is indistinguishable from the uniform
  distribution in the domain of the function F.

Additionally, we require the following additional properties:

- Non-malleable: Given (x, y = F(k, x)), V must not be able to generate (x', y')
  where x' != x and y' = F(k, x').
- Oblivious: P must learn nothing about V's input, and V must learn nothing
  about P's private key.
- Unlinkable: If V reveals x to P, P cannot link x to the protocol instance in
  which y = F(k, x) was computed.

Optionally, for any protocol that satisfies the above properties, there is an
additional security property:

- Verifiable: V must only complete execution of the protocol if it can
  successfully assert that P used its secret key k.

In practice, the notion of verifiability requires that P commits to the key k
before the actual protocol execution takes place. Then V verifies that P has
used k in the protocol using this commitment.

# OPRF Protocol {#protocol}

In this section we describe the OPRF protocol. Let GG be a prime-order additive
subgroup, with two distinct hash functions H_1 and H_2, where H_1 maps arbitrary
input onto GG and H_2 maps arbitrary input to a fixed-length output, e.g.,
SHA256. All hash functions in the protocol are modelled as random oracles. Let L
be the security parameter. Let k be the prover's (P) secret key, and Y = kG be
its corresponding 'public key' for some generator G taken from the group GG.
This public key is also referred to as a commitment to the key k. Let x be the
verifier's (V) input to the OPRF protocol. (Commonly, it is a random L-bit
string, though this is not required.)

The OPRF protocol begins with V blinding its input for the signer such that it
appears uniformly distributed GG. The latter then applies its secret key to the
blinded value and returns the result. To finish the computation, V then removes
its blind and hashes the result using H_2 to yield an output. This flow is
illustrated below.

~~~
     Verifier              Prover
  ------------------------------------
     r <-$ GG
     M = rH_1(x)
                   M
                ------->
                           Z = kM
                           [D = DLEQ_Generate(k,G,Y,M,Z)]
                  Z[,D]
                <-------
    [b = DLEQ_Verify(G,Y,M,Z,D)]
    N = Zr^(-1)
    Output H_2(x, N) [if b=1, else "error"]
~~~

Steps that are enclosed in square brackets (DLEQ_Generate and DLEQ_Verify) are
optional for achieving verifiability. These are described in Section {{dleq}}.
In the verifiable mode, we assume that P has previously committed to their
choice of key k with some values (G,Y=kG) and these are publicly known by V.
Notice that revealing (G,Y) does not reveal k by the well-known hardness of the
discrete log problem.

Strictly speaking, the actual PRF function that is computed is:

~~~
F(k, x) = N = kH_1(x)
~~~

It is clear that this is a PRF H_1(x) maps x to a random element in GG, and GG
is cyclic. This output is computed when the client computes Zr^(-1) by the
commutativity of the multiplication. The client finishes the computation by
outputting H_2(x,N). Note that the output from P is not the PRF value because
the actual input x is blinded by r.

This protocol may be decomposed into a series of steps, as described below:

- OPRF_Setup(l): Generate am integer k of sufficient bit-length l and output k.
- OPRF_Blind(x): Compute and return a blind, r, and blinded representation of x
  in GG, denoted M.
- OPRF_Sign(k,M): Sign input M using secret key k to produce Z.
- OPRF_Unblind(r,M,Z): Unblind blinded signature Z with blind r, yielding N and
  output N.
- OPRF_Finalize(x,N): Finalize N to produce the output H_2(x, N).

For verifiability we modify the algorithms of VOPRF_Setup, VOPRF_Sign and
VOPRF_Unblind to be the following:

- VOPRF_Setup(l): Generate am integer k of sufficient bit-length l and output
  (k, (G,Y)) where Y = kG for some generator G in GG.
- VOPRF_Sign(k,(G,Y),M): Sign input M using secret key k to produce Z. Generate
  a NIZK proof D = DLEQ_Generate(k,G,Y,M,Z), and output (Z, D).
- VOPRF_Unblind(r,G,Y,M,(Z,D)): Unblind blinded signature Z with blind r,
  yielding N. Output N if 1 = DLEQ_Verify(G,Y,M,Z,D). Otherwise, output "error".

We leave the rest of the OPRF algorithms unmodified. When referring explicitly
to VOPRF execution, we replace 'OPRF' in all method names with 'VOPRF'.

## Protocol correctness

Protocol correctness requires that, for any key k, input x, and (r, M) =
OPRF_Blind(x), it must be true that:

~~~
OPRF_Finalize(x, OPRF_Unblind(r,M,OPRF_Sign(k,M))) = H_2(x, F(k,x))
~~~

with overwhelming probability. Likewise, in the verifiable setting, we require
that:

~~~
VOPRF_Finalize(x, VOPRF_Unblind(r,G,Y,M,(VOPRF_Sign(k,M)))) = H_2(x, F(k,x))
~~~

with overwhelming probability, where (r, M) = VOPRF_Blind(x).

## Instantiations of GG

As we remarked above, GG is a subgroup with associated prime-order p. While we
choose to write operations in the setting where GG comes equipped with an
additive operation, we could also define the operations in the multiplicative
setting. In the multiplicative setting we can choose GG to be a prime-order
subgroup of a finite field FF_p. For example, let p be some large prime (e.g. >
2048 bits) where p = 2q+1 for some other prime q. Then the subgroup of squares
of FF_p (elements u^2 where u is an element of FF_p) is cyclic, and we can pick
a generator of this subgroup by picking g from FF_p (ignoring the identity
element).

For practicality of the protocol, it is preferable to focus on the cases where
GG is an additive subgroup so that we can instantiate the OPRF in the elliptic
curve setting. This amounts to choosing GG to be a prime-order subgroup of an
elliptic curve over base field GF(p) for prime p. There are also other settings
where GG is a prime-order subgroup of an elliptic curve over a base field of
non-prime order, these include the work of Ristretto {{RISTRETTO}} and Decaf
{{DECAF}}.

We will use p > 0 generally for constructing the base field GF(p), not just
those where p is prime. To reiterate, we focus only on the additive case, and so
we focus only on the cases where GF(p) is indeed the base field.

## Utility algorithms

## bin2scalar

This algorithm converts a binary string to an integer modulo p.

~~~
Input:

 s: binary string (little-endian)
 l: length of binary string
 p: modulus

Output:

 z: An integer modulo p

Steps:

 1. s_vec <- vec(s) (converts s to a column vector of dimension l)
 2. p2vec <- (2^0, 2^1, ..., 2^{l-1}) (row vector of dimension l)
 3. z <- p2vec * s_vec (mod p)
 4. Output z
~~~

## OPRF algorithms {#oprf}

This section provides algorithms for each step in the OPRF protocol. We describe
the VOPRF analogues in {{voprf}}

1. P samples a uniformly random key k <- {0,1}^l for sufficient length l, and
   interprets it as an integer.
2. V computes X = H_1(x) and a random element r (blinding factor) from GF(p),
   and computes M = rX.
3. V sends M to P.
4. P computes Z = kM = rkX.
5. In the elliptic curve setting, P multiplies Z by the cofactor (denoted h) of
   the elliptic curve.
6. P sends Z to V.
7. V unblinds Z to compute N = r^(-1)Z = kX.
8. V outputs the pair H_2(x, N).

### OPRF_Setup

~~~
Input:

 l: Some suitable choice of key-length (e.g. as described in {{NIST}}).

Output:

k: A key chosen from {0,1}^l and interpreted as an integer value.

Steps:

 1. Sample k_bin <-$ {0,1}^l
 2. Output k <- bin2scalar(k_bin, l)
~~~

### OPRF_Blind

~~~
Input:

 x: V's PRF input.

Output:

 r: Random scalar in [1, p - 1].
 M: Blinded representation of x using blind r, a point in GG.

Steps:

 1.  r <-$ GF(p)
 2.  M := rH_1(x)
 3.  Output (r, M)
~~~

### OPRF_Sign

~~~
Input:

 k: Signer secret key.
 M: Point in GG.

Output:

 Z: Scalar multiplication of the point M by k, point in GG.

Steps:

 1. Z := kM
 2. Z <- hZ
 3. Output Z
~~~

### OPRF_Unblind

~~~
Input:

 r: Random scalar in [1, p - 1].
 M: Blinded representation of x using blind r, a point in GG.
 Z: Point in GG.

Output:

 N: Unblinded signature, point in GG.

Steps:

 1. N := (-r)Z
 2. Output N
~~~

### OPRF_Finalize

~~~
Input:

 x: PRF input string.
 N: Point in GG.

Output:

 y: Random element in {0,1}^L.

Steps:

 1. y := H_2(x, N)
 2. Output y
~~~

## VOPRF algorithms {#voprf}

The steps in the VOPRF setting are written as:

1. P samples a uniformly random key k <- {0,1}^l for sufficient length l, and
   interprets it as an integer.
2. P commits to k by computing (G,Y) for Y=kG and where G is a generator of GG.
   P makes (G,Y) publicly available.
3. V computes X = H_1(x) and a random element r (blinding factor) from GF(p),
   and computes M = rX.
4. V sends M to P.
5. P computes Z = kM = rkX, and D = DLEQ_Generate(k,G,Y,M,Z).
6. P sends (Z, D) to V.
7. V ensures that 1 = DLEQ_Verify(G,Y,M,Z,D). If not, V outputs an error.
8. V unblinds Z to compute N = r^(-1)Z = kX.
9. V outputs the pair H_2(x, N).

### VOPRF_Setup

~~~
Input:

  l: Some suitable choice of key-length (e.g. as described in {{NIST}}).

Output:

  k: A key chosen from {0,1}^l and interpreted as an integer value.
  (G,Y): A commitment pair, where Y=kG for some generator G of GG.

Steps:

  1. k <- OPRF_Setup(l)
  2. Y := kG
  3. Output (k, (G,Y))
~~~

### VOPRF_Blind

~~~
Input:

 x: V's PRF input.

Output:

 r: Random scalar in [1, p - 1].
 M: Blinded representation of x using blind r, a point in GG.

Steps:

 1.  r <-$ GF(p)
 2.  M := rH_1(x)
 3.  Output (r, M)
~~~

### VOPRF_Sign

~~~
Input:

 G: Public generator of group GG.
 k: Signer secret key.
 Y: Signer public key (= kG).
 M: Point in GG.

Output:

 Z: Scalar multiplication of the point M by k, point in GG.
 D: DLEQ proof that log_G(Y) == log_M(Z).

Steps:

 1. Z := kM
 2. D = DLEQ_Generate(k,G,Y,M,Z)
 3. Output (Z, D)
~~~

### VOPRF_Unblind

~~~
Input:

 r: Random scalar in [1, p - 1].
 G: Public generator of group GG.
 Y: Signer public key.
 M: Blinded representation of x using blind r, a point in GG.
 Z: Point in GG.
 D: D = DLEQ_Generate(k,G,Y,M,Z).

Output:

 N: Unblinded signature, point in GG.

Steps:

 1. N := (-r)Z
 2. If 1 = DLEQ_Verify(G,Y,M,Z,D), output N
 3. Output "error"
~~~

### VOPRF_Finalize

~~~
Input:

 x: PRF input string.
 N: Point in GG, or "error".

Output:

 y: Random element in {0,1}^L, or "error"

Steps:

 1. If N == "error", output "error".
 2. y := H_2(x, N)
 3. Output y
~~~

# NIZK Discrete Logarithm Equality Proof {#dleq}

For the VOPRF protocol we require that V is able to verify that P has used its
private key k to evaluate the PRF. We can do this by showing that the original
commitment (G,Y) output by VOPRF_Setup(l) satisfies log_G(Y) == log_M(Z) where Z
is the output of VOPRF_Sign(k,M).

This may be used, for example, to ensure that P uses the same private key for
computing the VOPRF output and does not attempt to "tag" individual verifiers
with select keys. This proof must not reveal the P's long-term private key to V.

Consequently, this allows extending the OPRF protocol with a (non-interactive)
discrete logarithm equality (DLEQ) algorithm built on a Chaum-Pedersen
{{ChaumPedersen}} proof. This proof is divided into two procedures:
DLEQ_Generate and DLEQ_Verify. These are specified below.

## DLEQ_Generate

~~~
Input:

 k: Signer secret key.
 G: Public generator of group GG.
 Y: Signer public key (= kG).
 M: Point in GG.
 Z: Point in GG.
 H_3: A hash function from GG to {0,1}^L, modelled as a random oracle.

Output:

 D: DLEQ proof (c, s).

Steps:

 1. r <-$ GF(p)
 2. A := rG and B := rM.
 3. c <- H_3(G,Y,M,Z,A,B)
 4. s := (r - ck) (mod p)
 5. Output D := (c, s)
~~~

## DLEQ_Verify

~~~
Input:

 G: Public generator of group GG.
 Y: Signer public key.
 M: Point in GG.
 Z: Point in GG.
 D: DLEQ proof (c, s).

Output:

 True if log_G(Y) == log_M(Z), False otherwise.

Steps:

 1. A' := (sG + cY)
 2. B' := (sM + cZ)
 3. c' <- H_3(G,Y,M,Z,A',B')
 4. Output c == c'
~~~

# Batched VOPRF evaluation {#batch}

Common applications (e.g. {{PrivacyPass}}) require V to obtain multiple PRF
evaluations from P. In the VOPRF case, this would also require generation and
verification of a DLEQ proof for each Zi received by V. This is costly, both in
terms of computation and communication. To get around this, applications use a
'batching' procedure for generating and verifying DLEQ proofs for a finite
number of PRF evaluation pairs (Mi,Zi). For n PRF evaluations:

- Proof generation is slightly more expensive from 2n modular exponentiations to
  2n+2.
- Proof verification is much more efficient, from 4m modular exponentiations to
  2n+4.
- Communications falls from 2n to 2 group elements.

Therefore, since P is usually a powerful server, we can tolerate a slight
increase in proof generation complexity for much more efficient communication
and proof verification.

In this section, we describe algorithms for batching the DLEQ generation and
verification procedure. For these algorithms we require a pseudorandom generator
PRG: {0,1}^a x ZZ -> ({0,1}^b)^n that takes a seed of length a and an integer n
as input, and outputs n elements in {0,1}^b.

## Batched DLEQ algorithms

### Batched_DLEQ_Generate

~~~
Input:

 k: Signer secret key.
 G: Public generator of group GG.
 Y: Signer public key (= kG).
 n: Number of PRF evaluations.
 [Mi]: An array of points in GG of length n.
 [Zi]: An array of points in GG of length n.
 PRG: A pseudorandom generator of the form above.
 H_4: A hash function from GG^(2n+2) to {0,1}^a, modelled as a random oracle.

Output:

 D: DLEQ proof (c, s).

Steps:

 1. seed <- H_$(G,Y,[Mi,Zi]))
 2. d1,...dn <- PRG(seed,n)
 3. c1,...,cn := (int)d1,...,(int)dn
 4. M := c1M1 + ... + cnMn
 5. Z := c1Z1 + ... + cnZn
 6. Output D <- DLEQ_Generate(k,G,Y,M,Z)
~~~

### Batched_DLEQ_Verify

~~~
Input:

 G: Public generator of group GG.
 Y: Signer public key.
 [Mi]: An array of points in GG of length n.
 [Zi]: An array of points in GG of length n.
 D: DLEQ proof (c, s).

Output:

 True if log_G(Y) == log_(Mi)(Zi) for each i in 1...n, False otherwise.

Steps:

 1. seed <- H_$(G,Y,[Mi,Zi]))
 2. d1,...dn <- PRG(seed,n)
 3. c1,...,cn := (int)d1,...,(int)dn
 4. M := c1M1 + ... + cnMn
 5. Z := c1Z1 + ... + cnZn
 6. Output DLEQ_Verify(G,Y,M,Z,D)
~~~

## Modified protocol execution

The VOPRF protocol from Section {{protocol}} changes to allow specifying
multiple blinded PRF inputs [Mi] for i in 1...n. Then P computes the array [Zi]
and replaces DLEQ_Generate with Batched_DLEQ_Generate over these arrays. The
same applies to the algorithm VOPRF_Sign. The same applies for replacing
DLEQ_Verify with Batched_DLEQ_Verify when V verifies the response from P and
during the algorithm VOPRF_Verify.

# Elliptic Curve Group and Hash Function Instantiations {#ecinstantiation}

This section specifies supported ECVOPRF group and hash function instantiations.
We focus on the instantiations of the VOPRF in the elliptic curve setting for
now. Eventually, we would like to provide instantiations based on curves over
non-prime-order base fields.

ECVOPRF-P256-SHA256:

- G: P-256
- H_1: Simplified SWU encoding {{I-D.irtf-cfrg-hash-to-curve}}
- H_2: SHA256
- H_3: SHA256

ECVOPRF-P256-SHA512:

- G: P-256
- H_1: Simplified SWU encoding {{I-D.irtf-cfrg-hash-to-curve}}
- H_2: SHA512
- H_3: SHA512

ECVOPRF-P384-SHA256:

- G: P-384
- H_1: Icart encoding {{I-D.irtf-cfrg-hash-to-curve}}
- H_2: SHA256
- H_3: SHA256

ECVOPRF-P384-SHA512:

- G: P-384
- H_1: Icart encoding {{I-D.irtf-cfrg-hash-to-curve}}
- H_2: SHA512
- H_3: SHA512

ECVOPRF-CURVE25519-SHA256:

- G: Curve25519 {{RFC7748}}
- H_1: Elligator2 encoding {{I-D.irtf-cfrg-hash-to-curve}}
- H_2: SHA256
- H_3: SHA256

ECVOPRF-CURVE25519-SHA512:

- G: Curve25519 {{RFC7748}}
- H_1: Elligator2 encoding {{I-D.irtf-cfrg-hash-to-curve}}
- H_2: SHA512
- H_3: SHA512

ECVOPRF-CURVE448-SHA256:

- G: Curve448 {{RFC7748}}
- H_1: Elligator2 encoding {{I-D.irtf-cfrg-hash-to-curve}}
- H_2: SHA256
- H_3: SHA256

ECVOPRF-CURVE448-SHA512:

- G: Curve448 {{RFC7748}}
- H_1: Elligator2 encoding {{I-D.irtf-cfrg-hash-to-curve}}
- H_2: SHA512
- H_3: SHA512

# Security Considerations {#sec}

Security of the protocol depends on P's secrecy of k. Best practices recommend P
regularly rotate k so as to keep its window of compromise small. Moreover, it
each key should be generated from a source of safe, cryptographic randomness.

Another critical aspect of this protocol is reliance on
{{I-D.irtf-cfrg-hash-to-curve}} for mapping arbitrary inputs x to points on a
curve. Security requires this mapping be pre-image and collision resistant.

## Timing Leaks

To ensure no information is leaked during protocol execution, all operations
that use secret data MUST be constant time. Operations that SHOULD be constant
time include: H_1() (hashing arbitrary strings to curves) and DLEQ_Generate().
{{I-D.irtf-cfrg-hash-to-curve}} describes various algorithms for constant-time
implementations of H_1.

## Hashing to curves

We choose different encodings in relation to the elliptic curve that is used,
all methods are illuminated precisely in {{I-D.irtf-cfrg-hash-to-curve}}. In
summary, we use the simplified Shallue-Woestijne-Ulas algorithm for hashing
binary strings to the P-256 curve; the Icart algorithm for hashing binary
strings to P384; the Elligator2 algorithm for hashing binary strings to
CURVE25519 and CURVE448.

## Verifiability (key consistency)

DLEQ proofs are essential to the protocol to allow V to check that P's
designated private key was used in the computation. A side effect of this
property is that it prevents P from using unique key for select verifiers as a
way of "tagging" them. If all verifiers expect use of a certain private key,
e.g., by locating P's public key key published from a trusted registry, then P
cannot present unique keys to an individual verifier.

# Applications {#apps}

This section describes various applications of the VOPRF protocol.

## Privacy Pass

This VOPRF protocol is used by Privacy Pass system to help Tor users bypass
CAPTCHA challenges. Their system works as follows. Client C connects -- through
Tor -- to an edge server E serving content. Upon receipt, E serves a CAPTCHA to
C, who then solves the CAPTCHA and supplies, in response, n blinded points. E
verifies the CAPTCHA response and, if valid, signs (at most) n blinded points,
which are then returned to C along with a batched DLEQ proof. C stores the
tokens if the batched proof verifies correctly. When C attempts to connect to E
again and is prompted with a CAPTCHA, C uses one of the unblinded and signed
points, or tokens, to derive a shared symmetric key sk used to MAC the CAPTCHA
challenge. C sends the CAPTCHA, MAC, and token input x to E, who can use x to
derive sk and verify the CAPTCHA MAC. Thus, each token is used at most once by
the system.

The Privacy Pass implementation uses the P-256 instantiation of the VOPRF
protocol. For more details, see {{DGSTV18}}.

## Private Password Checker

In this application, let D be a collection of plaintext passwords obtained by
prover P. For each password p in D, P computes VOPRF_Sign(H_1(p)), where H_1 is
as described above, and stores the result in a separate collection D'. P then
publishes D' with Y, its public key. If a client C wishes to query D' for a
password p', it runs the VOPRF protocol using p as input x to obtain output y.
By construction, y will be the signature of p hashed onto the curve. C can then
search D' for y to determine if there is a match.

Examples of such password checkers already exist, for example: {{JKKX16}},
{{JKK14}} and {{SJKS17}}.

### Parameter Commitments

For some applications, it may be desirable for P to bind tokens to certain
parameters, e.g., protocol versions, ciphersuites, etc. To accomplish this, P
should use a distinct scalar for each parameter combination. Upon redemption of
a token T from V, P can later verify that T was generated using the scalar
associated with the corresponding parameters.

# Acknowledgements

This document resulted from the work of the Privacy Pass team {{PrivacyPass}}.
The authors would also like to acknowledge the helpful conversations with Hugo
Krawczyk.

--- back

# Test Vectors {#testvecs}

This section includes test vectors for the primary ECVOPRF protocol, excluding
DLEQ output.

((TODO: add DLEQ vectors))

~~~
P-224
X: 0403cd8bc2f2f3c4c647e063627ca9c9ac246e3e3ec74ab76d32d3e999c522d60ff7aa1c8b0e4 \
   X: 0403cd8bc2f2f3c4c647e063627ca9c9ac246e3e3ec74ab76d32d3e999c522d60ff7aa1c8b0e4
r: c4cf3c0b3a334f805d3ce3c3b4d007fbbdaf078a42a8cbdc833e54a9
M: 046b2b8482c36e65f87528415e210cff8561c1c8e07600a159893973365617ee2c1c33eb0662d \
   M: 046b2b8482c36e65f87528415e210cff8561c1c8e07600a159893973365617ee2c1c33eb0662d
k: a364119e1c932a534a8d440fef2169a0e4c458d702eca56746655845
Z: 04ed11656b4981e39242b170025bf8d5314bef75006e6c4c9afcdb9a85e21fb5fcf9055eb95d3 \
   Z: 04ed11656b4981e39242b170025bf8d5314bef75006e6c4c9afcdb9a85e21fb5fcf9055eb95d3
Y: 04fd80db5301a54ee2cbc688d47cbcae9eb84f5d246e3da3e2b03e9be228ed6c57a936b6b5faf \
   Y: 04fd80db5301a54ee2cbc688d47cbcae9eb84f5d246e3da3e2b03e9be228ed6c57a936b6b5faf

P-224
X: 0429e41b7e1a58e178afc522d0fb4a6d17ae883e6fd439931cf1e81456ab7ed6445dbe0a231be \
   X: 0429e41b7e1a58e178afc522d0fb4a6d17ae883e6fd439931cf1e81456ab7ed6445dbe0a231be
r: 86a27e1bd51ac91eae32089015bf903fe21da8d79725edcc4dc30566
M: 04d8c8ffaa92b21aa1cc6056710bd445371e8afebd9ef0530c68cd0d09536423f78382e4f6b20 \
   M: 04d8c8ffaa92b21aa1cc6056710bd445371e8afebd9ef0530c68cd0d09536423f78382e4f6b20
k: ab449c896261dc3bd1f20d87272e6c8184a2252a439f0b3140078c3d
Z: 048ac9722189b596ffe5cb986332e89008361e68f77f12a931543f63eaa01fabf6f63d5d4b3b6 \
   Z: 048ac9722189b596ffe5cb986332e89008361e68f77f12a931543f63eaa01fabf6f63d5d4b3b6
Y: 046e83dff2c9b6f9e88f1091f355ad6fa637bdbd829072411ea2d74a5bf3501ccf3bcc2789d48 \
   Y: 046e83dff2c9b6f9e88f1091f355ad6fa637bdbd829072411ea2d74a5bf3501ccf3bcc2789d48

P-256
X: 041b0e84c521f8dcd530d59a692d4ffa1ca05b8ba7ce22a884a511f93919ac121cc91dd588228 \
   X: 041b0e84c521f8dcd530d59a692d4ffa1ca05b8ba7ce22a884a511f93919ac121cc91dd588228
r: a3ec1dc3303a316fc06565ace0a8910da65cf498ea3884c4349b6c4fc9a2f99a
M: 04794c5a54236782088594ccdb1975e93b05ff742674cc400cb101f55c0f37e877c5ada0d72fb \
   M: 04794c5a54236782088594ccdb1975e93b05ff742674cc400cb101f55c0f37e877c5ada0d72fb
k: 9c103b889808a8f4cb6d76ea8b634416a286be7fa4a14e94f1478ada7f172ec3
Z: 0484cfda0fdcba7693672fe5e78f4c429c096ece730789e8d00ec1f7be33a6515f186dcf7aa38 \
   Z: 0484cfda0fdcba7693672fe5e78f4c429c096ece730789e8d00ec1f7be33a6515f186dcf7aa38
Y: 044ff2e31de9fda542c2c63314e2bce5ce2d5ccb8332dbe1115ff5740e5e60bb867994e196ead \
   Y: 044ff2e31de9fda542c2c63314e2bce5ce2d5ccb8332dbe1115ff5740e5e60bb867994e196ead

P-256
X: 043ea9d81b99ac0db002ad2823f7cab28af18f83419cce6800f3d786cc00b6fd030858d073916 \
   X: 043ea9d81b99ac0db002ad2823f7cab28af18f83419cce6800f3d786cc00b6fd030858d073916
r: ed7294b42792760825645b635e9d92ef5a3baa70879dd59fdb1802d4a44271b2
M: 04ec894e496d0297756a17365f866d9449e6ebc51852ab1ffa57bc29c843ef003b116f5ef1f60 \
   M: 04ec894e496d0297756a17365f866d9449e6ebc51852ab1ffa57bc29c843ef003b116f5ef1f60
k: a324338a7254415dbedcd1855abd2503b4e5268124358d014dac4fc2c722cd67
Z: 04a477c5fefd9bc6bcd8e893a1b0c6dc73b0bd23ebe952dcad810de73b8a99f5e1e216a833b32 \
   Z: 04a477c5fefd9bc6bcd8e893a1b0c6dc73b0bd23ebe952dcad810de73b8a99f5e1e216a833b32
Y: 04ffe55e2a95a21e1605c1ed11ac6bea93f00fa15a6b27e90adad470ad27f0e0fe5b8607b4689 \
   Y: 04ffe55e2a95a21e1605c1ed11ac6bea93f00fa15a6b27e90adad470ad27f0e0fe5b8607b4689

P-384
X: 04c0b51e5dcd6a309c77bb5720bf9850279e8142b6127952595ab9092578de810a13795bceff3 \
   d358f0480a61469f17ad62ebaecd0f817c1e9c7d41d536ab410e7a2b5d7a7905d1bef5499b654b0e \
   d358f0480a61469f17ad62ebaecd0f817c1e9c7d41d536ab410e7a2b5d7a7905d1bef5499b654b0e
r: 889b5e4812d683c4df735971240741ff869ccf77e10c2e97bef67d6fe6b8350abe59ec8fe2bfa \
   r: 889b5e4812d683c4df735971240741ff869ccf77e10c2e97bef67d6fe6b8350abe59ec8fe2bfa
M: 044e2d86fa6e53ebba7f2a9b661a2de884a8ccc68e29b68586d517eb66e8b4b7dac334c6e769d \
   485d672fac3a0311877572254754e318077aec3631208c6b503c5cdfe57716e1232da64cebe46f0d \
   485d672fac3a0311877572254754e318077aec3631208c6b503c5cdfe57716e1232da64cebe46f0d
k: b8c854a33c8c564d0598b1ac179546acdccad671265cff1ea5a329279272e8d21c94b7e5b6bea \
   k: b8c854a33c8c564d0598b1ac179546acdccad671265cff1ea5a329279272e8d21c94b7e5b6bea
Z: 047bf23eef00e83e6cb6fb9ade5e5995cf81abb8dc73a570ff4cb7be48f21281edfed9bf76cc2 \
   88b35d2df615ff711ed2a1fb85cd0b22812438665cdd300039685b3f593f4b574f9e8b294982c2a2 \
   88b35d2df615ff711ed2a1fb85cd0b22812438665cdd300039685b3f593f4b574f9e8b294982c2a2
Y: 04ab4886ecf7e489a0be8529ff4b537941c95ba4ce570db537dcfad5cabc064c43f1b0a1d1b89 \
   101facd93f2f9a8b5f28431489be4664f446af8a51cc7c4221f633adb4f8f2f2a073dfd83ddf8d77 \
   101facd93f2f9a8b5f28431489be4664f446af8a51cc7c4221f633adb4f8f2f2a073dfd83ddf8d77

P-384
X: 047511a846277a2009f37b3583f14c8ea3af17e3a146e0e737fdc1260b6d4a18ff01f21ec3bbc \
   e39e1cade76d455feadc1bb16f65cd54042e1bc5aba1dee2434f59d00698a963b902148750240f8f \
   e39e1cade76d455feadc1bb16f65cd54042e1bc5aba1dee2434f59d00698a963b902148750240f8f
r: e514ef9b3ea87eafdb78da48e642daa79f036ac00228997ab8da6ac198fb888cd2fec84d52010 \
   r: e514ef9b3ea87eafdb78da48e642daa79f036ac00228997ab8da6ac198fb888cd2fec84d52010
M: 04fd9b68973b0fcefcf4458b4faa1c3815bdad8975b7fb0bfc4c1db7e3f169fb3a26ddabe1b25 \
   c4a23cf8a2faeb12c18f06f2227e87ede6039f55a61ef0c89ca3c582e2864fe130ea0c709f92519d \
   c4a23cf8a2faeb12c18f06f2227e87ede6039f55a61ef0c89ca3c582e2864fe130ea0c709f92519d
k: bcc73da3b2adace9c4f4c32eeadef57436c97f8d395614e78aa91523e1e5d7f551ebb55e87da2 \
   k: bcc73da3b2adace9c4f4c32eeadef57436c97f8d395614e78aa91523e1e5d7f551ebb55e87da2
Z: 042d885d2945cde40e490dd8497975eaeb54e4e10c5986a9688c9de915b16cf43572fd155e159 \
   9e2233a75056a72b54d30092e30bb2edc70e0d90da934c27362e0e6303bafae12f13bf3d5be322e6 \
   9e2233a75056a72b54d30092e30bb2edc70e0d90da934c27362e0e6303bafae12f13bf3d5be322e6
Y: 044833fba4973c1c6eae6745850866ebbb23783ea0d4d8b867e2c93acb2f01fd3d36d9cb5c491 \
   ff9440c8c8e325db326bf88ddf0ba6008158a67999e18cd378d701d1f8a6a7b088dc261c85b6a78b \
   ff9440c8c8e325db326bf88ddf0ba6008158a67999e18cd378d701d1f8a6a7b088dc261c85b6a78b

P-521
X: 040039d290b20c604b5c59cb85dfacd90cbf9f5e275ee8c38a8ff80df0872e8e1dd214a9ec3b2 \
   2c8d75bf634739afdc09acc342542abacf35bf2a6488d084825c5d96003be29e201e75c1b78667f5 \
   a64cc7207722796b225b49edaaf457fcafff4f644252ebe8057291d317f30109f1526aacbfff2308 \
   a64cc7207722796b225b49edaaf457fcafff4f644252ebe8057291d317f30109f1526aacbfff2308
r: 010606612666705556ac3c28dde30f134e930b0c31bfc9715f0812e0b99f0212dc427e344cb97 \
   r: 010606612666705556ac3c28dde30f134e930b0c31bfc9715f0812e0b99f0212dc427e344cb97
M: 040065366112a0598e4e5997e79e42f287f7202e5d956bef29890e963169d9eaab8d21501283c \
   47dd37aca1710c8b5f456b1c044c8582ba6feef3edc997fecef7d4f40180ceb9bbbe3ab1907ea2d1 \
   21ec00156848e04e323744d86444111fc09a21ca316df2cae925a0bb079d0faa2474ec8d5a96e6fa \
   21ec00156848e04e323744d86444111fc09a21ca316df2cae925a0bb079d0faa2474ec8d5a96e6fa
k: 01297d92cfe6895269aa5406f2ba6cbfffbba66a11ab0db34655213624fa238c50e27177aea5d \
   k: 01297d92cfe6895269aa5406f2ba6cbfffbba66a11ab0db34655213624fa238c50e27177aea5d
Z: 040151d2dc5290ebd47065680dcb4db350c4d81346680c5589f94acfb1e28418585e7f2cbfa11 \
   5945d9f7b98157ea8c2ab190c6a47b939502c2f793b77ceff671f5e60086fdd1ebf960f29bf5d590 \
   f8f7511d248df22d964637e2286adab4654991d338691f4673a006ff116e61afe65c914b27c3ef4c \
   f8f7511d248df22d964637e2286adab4654991d338691f4673a006ff116e61afe65c914b27c3ef4c
Y: 04009534bd720bd4ebe703968a8496eec352711a81b7fe594a72ef318c2ce582b41880262a1c6 \
   05079231de91e71b1301d1be4e9618e96081ccfd4f6cab92f52b860e01beec2c58cb01713e941035 \
   adbe882ab4f3eaa31e27a96d210d35f6161b1487dd28d8da4a11a915182752b1450a89aad2a013c2 \
   adbe882ab4f3eaa31e27a96d210d35f6161b1487dd28d8da4a11a915182752b1450a89aad2a013c2

P-521
X: 04012ea416842dfad169a9eb860b0af2af3c0140e1918ccd043650d83ad261633f20c5ca02c1b \
   ffb857ab72814cf46cfc16ac9ba79887044709f72480358c4b990e46010a62336bb57b87b494b064 \
   4d2b6a385f3d5b5da29e22cae33c624f561513a5e8e6669b4e99704c56157dde83994a3c0800a64b \
   4d2b6a385f3d5b5da29e22cae33c624f561513a5e8e6669b4e99704c56157dde83994a3c0800a64b
r: 019d02efd97add5facc5defbb63fd74daaacda04ae7321abec0da1551b4cc980b8ce6855a28a1 \
   r: 019d02efd97add5facc5defbb63fd74daaacda04ae7321abec0da1551b4cc980b8ce6855a28a1
M: 040066e3d0b5b9758c9288a725ce6724fdc3bd797a8222f07233897a5916dc167531ebc6a4710 \
   cbb240684c9a02eb82214b009d636f24abb8e409e78ff1f02a1dbfb90069056693e96acd760887f9 \
   6c9b1f487441b7142fb13a67deb7332194ff454b3aac89f9cf02c338dae69a700bd26844881e6106 \
   6c9b1f487441b7142fb13a67deb7332194ff454b3aac89f9cf02c338dae69a700bd26844881e6106
k: 018eeea896de104bf1e772155836f6ceddab0b4c2e3e4c33ba08a6fd6db0291cfb15faff0b3c7 \
   k: 018eeea896de104bf1e772155836f6ceddab0b4c2e3e4c33ba08a6fd6db0291cfb15faff0b3c7
Z: 04016825ea754324d5761ada130a1b87b03b5e2a6b0f403343925c67df39bbf85bc782909124d \
   d297a1edfb049efa7ce61c626c0ad99d8cf462abcce1ee1967d8a355011e2c5a7ce621fc822a7d95 \
   bf7359d938ee4a5c3431e7dd270b7fb6e95fda29cf460d89454763bb0db9b8b705503170a9ac1c7a \
   bf7359d938ee4a5c3431e7dd270b7fb6e95fda29cf460d89454763bb0db9b8b705503170a9ac1c7a
Y: 04006b0413e2686c4bb62340706de7723471080093422f02dd125c3e72f3507b9200d11481468 \
   74bbaa5b6108b834c892eeebab4e21f3707ee20c303ebc1e34fcd3c701f2171131ee7c5f07c1ccad \
   240183d777181259761741343959d476bbc2591a1af0a516e6403a6b81423234746d7a2e8c2ce60a \
   240183d777181259761741343959d476bbc2591a1af0a516e6403a6b81423234746d7a2e8c2ce60a
~~~