# LibDisco

The `libdisco` package contained in this folder is a **plug-and-play** secure protocol and library based on the [Noise protocol framework](https://noiseprotocol.org) and [Strobe protocol framework](https://strobe.sourceforge.io). It has been implemented following the same patterns used in [crypto/tls](https://golang.org/pkg/crypto/tls/).

This has use cases close to TLS: it allows you to encrypt communications.

**This software is experimental. You must not use this in production.**

[![Build Status](https://travis-ci.org/mimoo/disco.svg?branch=master)](https://travis-ci.org/mimoo/disco)

## Documentation

head over at [www.discocrypto.com](https://www.discocrypto.com)

## Roadmap

- [ ] need more tests
- [ ] need test vectors 
- [ ] need some benchmarks
- [ ] Noise_NN could be implemented via ShortAuthenticationString/fingerprint post-handshake. The Cipherstate wouldn't be usable before activating them via a fingerprint. You would also have an export function that would generate that fingerprint 