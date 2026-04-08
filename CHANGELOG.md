# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-08

### Added

- Add key agreement support.
- Add certification path validation support.
- Add PKCS#8 support for private key information storage.
- Add AES-CCM support.
- Add stub implementation of the external key store support.
- Add stub implementation of the AES Key Wrap support.

### Changed

- Async worker implementation of `LLSEC_KEY_FACTORY_ec_public_key_from_raw` and `LLSEC_PRIVATE_KEY_get_encoded`.
- Allow the user to set a custom heap instead of forcing the system heap.
- Code standardization among sources of the module.

### Fixed

- Fix `LLSEC_KEY_FACTORY_IMPL_get_ec_public_key_from_raw` by removing the signed byte of affine x and affine y BigInterger byte arrays.
- Fix `LLSEC_KEY_FACTORY_IMPL_get_ec_public_key_from_raw` `curveName` async worker parameter setup.

## [1.0.0] - 2025-02-28

- Initial revision.

---
_Copyright 2025-2026 MicroEJ Corp. All rights reserved._
_Use of this source code is governed by a BSD-style license that can be found with this software._
