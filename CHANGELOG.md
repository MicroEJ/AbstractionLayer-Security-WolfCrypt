# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-09-16

### Added

- Add support for AES secret keys held in a PKCS#11 token and addressed by label.

### Changed

- Migrate from the Security Foundation Library `LLSEC` API to the Crypto Foundation Library `LLCRYPTO` API. Migration: rename every `LLSEC_` file, symbol and configuration macro to `LLCRYPTO_`, and every `llsec_` helper to `llcrypto_`.
- Return `LLCRYPTO_ERROR_OOM` on allocation failures so the Crypto library can run a garbage collection and retry.
- Require wolfSSL 5.8.4 or higher.
- Report an unsupported AES Key Wrap transformation as the exception declared by `Cipher.getInstance()` instead of a native exception.
- Report a refused cipher initialization as the exception declared by `Cipher.init()` instead of a native exception.
- Raise the longest additional authenticated data accepted by the AES/GCM and AES/CCM ciphers from 16 to 256 bytes (`LLCRYPTO_CIPHER_MAX_AAD_LENGTH`).
- Rename the asynchronous job states of `LLCRYPTO_common.h` to `LLCRYPTO_JOB_*` so they cannot be mistaken for the `LLCRYPTO_ERROR_*` codes of the Crypto library. Migration: replace `LLCRYPTO_ERROR_EXCEPTION`, `LLCRYPTO_ERROR_NO_JOB` and `LLCRYPTO_ERROR_NOT_COMPLETED` with `LLCRYPTO_JOB_EXCEPTION`, `LLCRYPTO_JOB_UNAVAILABLE` and `LLCRYPTO_JOB_NOT_COMPLETED`.

### Fixed

- Fix memory leaks and missing null checks on allocation failure paths.
- Fix the Core Engine fault when a cipher operation runs on a cipher whose initialization failed.
- Fix MAC debug traces being controlled by the random generator debug flag.
- Fix the AES/GCM cipher on a key held in RAM: the authentication tag was wrong and the decrypt always failed.
- Fix the AES/GCM and AES/CCM decrypt to report an authentication failure as `AEADBadTagException` instead of a native exception.

### Security

- Wipe secret key material and shared secrets before releasing their memory.

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
