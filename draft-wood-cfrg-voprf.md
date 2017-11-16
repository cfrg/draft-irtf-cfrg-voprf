---
title: Verifiable Oblivious Pseudorandom Functions (VOPRFs)
abbrev: VOPRFs
docname: draft-wood-cfrg-voprf
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: N. Sullivan
    name: Nick Sullivan
    org: Cloudflare
    street: XXX
    city: XXX
    country: United States of America
    email: XXX
  -
    ins: C. A. Wood
    name: Christopher A. Wood
    org: Apple
    street: XXX
    city: XXX
    country: United States of America
    email: XXX

normative:
  RFC2119:
  PrivacyPass:
    title: Privacy Pass
    target: https://github.com/privacypass/challenge-bypass-server
  ChaumBlindSignature:
    title: Blind Signatures for Untraceable Payments
    target: http://sceweb.sce.uhcl.edu/yang/teaching/csci5234WebSecurityFall2011/Chaum-blind-signatures.PDF
    authors:
      -
        ins: D. Chaum
        org: University of California, Santa Barabara, USA

--- abstract

XXX

--- middle

# Introduction

A Verifiable Oblivious Pseudorandom Function (VOPRF) is a two-party protocol
between a requestor and signer for obliviously computing a verifiable, 
public-key, cryptographic hash. The signer uses its private key to help the
requestor compute the VOPRF output without learning the requestor's input. 
VOPRFs are useful for producing tokens that are verifiable by the signer yet 
unlinkable to the original requestor. They are used in the Privacy Pass 
protocol {{PrivacyPass}}. This document is structured as follows:

- Section XXX: Describe background and work related to VOPRF protocols.
- Section XXX: Discuss the security properties of such protocols.
- Section XXX: Specify a VOPRF protocol based on elliptic curve groups. 
- Section XXX: Specify a VOPRF extension that permits signers to prove the private key was integrated into the VOPRF computation.
- Section XXX: Discuss implementation status and existing use cases.

## Terminology

XXX

- PRF:
- VOPRF:
- DLEQ: 
- Prover: The Prover holds the private VRF key SK and public VRF key PK.
- Verifier: The Verifier holds the public VRF key PK.

## Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

# Background

VOPRFs are related to, e.g., RSA-based blind signature schemes {{ChaumBlindSignature}}.
Such a scheme works as follows. 
Let m be a message to be signed by a server. It is assumed to be a member of the 
RSA group. Also, let N be the RSA modulus, and e and d be the public and private keys, 
respectively. The requestor and signer engage in the following protocol.

1. Generate a random blinding element r from the RSA group.
2. Send m' to the server.
3. Sign m' by computing s' = (m')^d (mod; N)
4. Send s' to the client.
5. Remove the blinding factor r to obtain the original signature as s = (s')^{r^-1}.

By the properties of RSA, s is clearly a valid signature for m. 
(V)OPRF protocols differ from blind signatures in the same way that 
traditional digital signatures differ from PRFs. 

# Security Properties

The security properties of a VOPRF protocol with functionality y = F(k, x) are similar 
to that of a PRF. Specifically:

- Given value x, it is infeasible to learn y = F(k, x) without knowledge of k.
- The output y = F(k, x) is indistinguishable from a random value in the domain of F. 

Additionally, since this is an oblivious protocol, the following security properties
are required:

- The signer must learn nothing about the requestor's input.
- The requestor must learn nothing about the signer's private key.

# Elliptic Curve VOPRF

Let G be a group with two distinct hash functions H_1 and H_2 that map arbitrary
input onto G. Let L be the security parameter. Let x be the signer's private key,
and Y = xG be its corresponding public key. Let t be the requestor's input to
the VOPRF protocol. (Commonly, it is generated as a random L-bit string, though
this is not required.) The protocol works by having the requestor randomly blind
its input for the signer. The latter then applies its private key to the blinded
value and returns the result, at which point the requestor can remove the blind
and output the VOPRF value. This general flow is shown below.

~~~
    Requestor               Signer
     r <-$ G
     M = rH_1(t) 
                   M
                ------->    
                           Z = xM
                   Z
                <-------
    N = Zr^(-1)    
~~~

The specific steps and computations in this protocol are enumerated below.

1. Requestor computes T = H_1(t) and a random element r from G. (The latter is the
blinding factor.) The requestor computes M = rT.
2. Requestor sends M to the signer. 
3. Signer computes Z = xM = rxT. 
4. Signer sends Z to the requestor.
5. Requestor unblinds Z to compute N = r^(-1)Z = xT.
6. Requestor outputs the pair (t, N).

## Group Instantiations

- EC-VOPRF-CURVE25519-SHA256:
- EC-VOPRF-CURVE25519-SHA512:
- EC-VOPRF-ED25519-SHA256:
- EC-VOPRF-ED25519-SHA512:

# Private Key Proofs

In some cases, it may be desireable for the requestor to have proof that the signer
used its private key to compute Z. To do so, we extend the protocol in the previous
section with a non-interactive discrete logarithm equality (DLEQ) proof. 

XXX

# IANA Considerations

TODO

# Security Considerations

TODO

# Acknowledgments

TODO

