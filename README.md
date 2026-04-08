![ARCH](https://shields.microej.com/endpoint?url=https://repository.microej.com/packages/badges/net_13.json)

# Abstraction Layer Security with wolfCrypt (wolfSSL) stack.

# Overview

This Abstraction Layer (ABLA) implements the Low Level API `LLSEC` needed by the MicroEJ Security foundation library to connect to a Board Support Package using the [wolfCrypt/wolfSSL](https://www.wolfssl.com/) stack.

See the MicroEJ documentation for a description of the `LLSEC` functions:

- [LLSEC: Security](https://docs.microej.com/en/latest/VEEPortingGuide/appendix/llapi.html#llsec-security)
- [Security: Installation](https://docs.microej.com/en/latest/VEEPortingGuide/security.html#installation)
- [Security functional architecture](https://docs.microej.com/en/latest/ApplicationDeveloperGuide/networking.html)

This implementation has a default configuration file, [LLSEC_configuration.h](src/main/c/inc/LLSEC_configuration.h).

# Usage

1. These sources can be included in the VEE Port with the method you prefer, by using this repository as a submodule or by doing a copy of the sources in the VEE Port repository.

2. The configuration file `LLSEC_configuration.h` stores default values of the abstraction layer configuration. If you want to update a configuration, please edit or create the file `veeport_configuration.h` and set the desired value. This setting overwrites the content of `LLSEC_configuration.h`. 

3. Enable debug logs: if your VEE Port does not print logs using printf, the trace redirection macro `LLSEC_DEBUG_TRACE` can be updated in `veeport_configuration.h`. Then, enable the desired debug logs by setting `LLSEC_DEBUG_TRACE_ENABLE` to the target debug macro, i.e. `LLSEC_CIPHER_DEBUG`. Note that all logs can be enabled with the macro `LLSEC_ALL_DEBUG`.

4. Use a custom heap with this ABLA: wolfCrypt functions can use either the system's heap or a custom heap provided by the user. This ABLA and wolfCrypt uses by default the system's heap with a provided weak implementation of the function `llsec_wolfssl_get_heap`. This implementation can be overridden to allow to provide a custom heap dedicated to this ABLA and wolfCrypt stack. Please, update  the macros `LLSEC_CALLOC_IMPL` and `LLSEC_FREE_IMPL` when a custom heap is used.


# Requirements

N/A

# Validation

This Abstraction Layer implementation can be validated in the target Board Support Package using the Security Foundation library testsuite. A testsuite runner module is available in the [Tool-Project-Template-VEEPort](https://github.com/MicroEJ/Tool-Project-Template-VEEPort/tree/master/vee-port/validation/security) on Github.
Here is a non exhaustive list of tested environments:

- Hardware
  - STMicroelectronics STM32U5G9 custom board.
- Compilers / Integrated Development Environments:
  - IAR Embedded Workbench 9.50.1
  - IAR Embedded Workbench 9.60.4
- Stack versions:
  - WolfSSL 5.7.2
  - WolfSSL 5.8.4

# MISRA Compliance

This Abstraction Layer implementation is MISRA-compliant (MISRA C:2012) with some noted exception.
It has been verified with Cppcheck v2.13. Here is the list of deviations from MISRA standard:

| Deviation   | Category | Justification                                                         |
|:-----------:|:--------:|:--------------------------------------------------------------------- |
|  Rule 2.5   | Advisory | A macro can be defined at API level and not used by the application.  |
|  Rule 8.4   | Required | A compatible declaration is defined in headers provided by the VEE Port. |
|  Rule 8.7   | Advisory | API function that can be used in another file.                        |
|  Rule 8.9   | Advisory | Define here for code readability even if it called once in this file. |
|  Rule 10.8  | Required | Number in [0, 25] range.                                              |
|  Rule 11.1  | Required | Abstract data type for SNI usage.                                     |
|  Rule 11.3  | Required | From sni.h with SNI_getArrayLength, cast used by many C framework to factorize code. |
|  Rule 11.4  | Advisory | Abstract data type for SNI usage.                                     |
|  Rule 11.5  | Advisory | Abstract data type for SNI usage.                                     |
|  Rule 11.6  | Required | Abstract data type for SNI usage.                                     |
|  Rule 11.8  | Required | The SNI API does not use the const keyword.                           |
|  Rule 17.8  | Advisory | Can be useful when designing C library.                               |
|  Rule 18.4  | Advisory | From sni.h with SNI_getArrayLength, used for configurable C library.  |
|  Rule 19.2  | Advisory | Generic justification, is useful when designing C library.            |
|  Rule 20.9  | Advisory | A compatible declaration is defined in headers provided by the VEE Port. |
|  Rule 20.10 | Advisory | Used by MicroEJ architectures.                                        |
|  Rule 21.3  | Required | Usage sometime forced by BSP                                          |
|  Rule 21.6  | Required | Include only in debug.                                                |
|  Rule 21.10 | Required | Used by POSIX platforms.                                              |

# Dependencies

- WolfSSL 5.7.x or higher (tested up to 5.8.4)

# Source

N/A

# Restrictions

None.

---
_Copyright 2025-2026 MicroEJ Corp. All rights reserved._
_Use of this source code is governed by a BSD-style license that can be found with this software._
