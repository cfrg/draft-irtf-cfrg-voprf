# Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups

This is the working area for the individual Internet-Draft, "Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups".

* [Editor's Copy](https://cfrg.github.io/draft-irtf-cfrg-voprf/#go.draft-irtf-cfrg-voprf.html)
* [Individual Draft](https://tools.ietf.org/html/draft-irtf-cfrg-voprf)
* [Compare Editor's Copy to Individual Draft](https://cfrg.github.io/draft-irtf-cfrg-voprf/#go.draft-irtf-cfrg-voprf.diff)

## Building the Draft

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

This requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/master/doc/SETUP.md).

## Existing Implementations

| Implementation                                                            | Language   | Version  | Modes  |
| ------------------------------------------------------------------------- |:-----------|:---------|:-------|
| [**Reference**](https://github.com/cfrg/draft-irtf-cfrg-voprf/tree/draft-irtf-cfrg-voprf-09/poc)  | Sage/Python | draft-10 | All |
| [oprf-ts](https://github.com/privacyresearchgroup/oprf-ts)                | TypeScript | draft-07 | All    |
| [voprf-ts](https://github.com/cloudflare/voprf-ts)                        | TypeScript | draft-10 | All    |
| [voprf](https://github.com/bytemare/voprf)                                | Go         | draft-10 | All    |
| [CIRCL](https://github.com/cloudflare/circl)                              | Go         | draft-10 | All    |
| [voprf](https://github.com/novifinancial/voprf)                           | Rust       | main     | All    |
| [BoringSSL](https://boringssl.googlesource.com/boringssl/+/refs/heads/master/crypto/trust_token/) | C      | draft-04 | All    |
| [ecc](https://github.com/aldenml/ecc)                                     | C          | draft-08 | All    |

### Other Integrations

| Implementation                                                            | Language | Version  | Modes  | Notes |
| ------------------------------------------------------------------------- |:---------|:---------|:-------|:------|
| [opaque-ke](https://github.com/novifinancial/opaque-ke/)                  | Rust     | draft-06 | Base   | As a component for OPAQUE |
| [opaque](https://github.com/bytemare/opaque)                              | Go       | draft-10 | Base   | As a component for OPAQUE |
| [libopaque](https://github.com/stef/libopaque)                            | C        | draft-09 | Base   | As a component for OPAQUE |

Submit a PR if you have a compliant implementation!

## Contributing

See the
[guidelines for contributions](https://github.com/cfrg/draft-irtf-cfrg-voprf/blob/master/CONTRIBUTING.md).
