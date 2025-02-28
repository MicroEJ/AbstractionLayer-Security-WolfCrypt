![SDK](https://shields.microej.com/endpoint?url=https://repository.microej.com/packages/badges/sdk_5.8.json)
![ARCH](https://shields.microej.com/endpoint?url=https://repository.microej.com/packages/badges/arch_8.1.json)

# MicroEJ C Component for Security foundation usage with Wolfcrypt (WolfSSL) stack. 

# Overview

This component implements the Low Level API `LLSEC` needed by the MicroEJ Security foundation library to connect to a Board Support Package using the Woftcrypt/WolfSSL stack.

See the MicroEJ documentation for a description of the `LLSEC` functions:
- [LLSEC: Security](https://docs.microej.com/en/latest/VEEPortingGuide/appendix/llapi.html#llsec-security)
- [Security: Installation](https://docs.microej.com/en/latest/VEEPortingGuide/security.html#installation)
- [Security functional architecture](https://docs.microej.com/en/latest/ApplicationDeveloperGuide/networking.html)

This implementation has a default configuration file, [LLSEC_configuration.h](src/main/c/inc/LLSEC_configuration.h). This component support user configuration parameters in the `veeport_configuration.h` file.

# Usage

Add the following line to your `module.ivy` or your `ivy.xml`:
> `<dependency org="com.microej.clibrary.llimpl" name="crypto-wolfssl" rev="1.0.0"/>`

# Requirements

N/A

# Validation


- Hardware
  - STMicroelectronics STM32U5G9 customer board.
- Compilers / Integrated Development Environments:
  - IAR Embedded Workbench 9.50.1
- Stack versions:
  - WolfSSL 5.7.2

# MISRA Compliance

This Abstraction Layer implementation is MISRA-compliant (MISRA C:2012) with some noted exception.
It has been verified with Cppcheck v2.10. Here is the list of deviations from MISRA standard:

| Deviation  | Category | Justification                                                         |
|:----------:|:--------:|:--------------------------------------------------------------------- |
|  Rule 8.7  | Advisory | API function that can be used in another file.                        |
|  Rule 8.9  | Advisory | Define here for code readability even if it called once in this file. |
|  Rule 10.8 | Required | Number in [0, 25] range                                               |
|  Rule 11.1 | Required | Abstract data type for SNI usage                                      |
|  Rule 11.3 | Required | From sni.h with SNI_getArrayLength, cast used by many C framework to factorize code.                                     |
|  Rule 11.4 | Advisory | Abstract data type for SNI usage                                      |
|  Rule 11.5 | Advisory | Abstract data type for SNI usage                                      |
|  Rule 11.6 | Required | Abstract data type for SNI usage                                      |
|  Rule 18.4 | Advisory | From sni.h with SNI_getArrayLength, used for configurable C library.  |
|  Rule 19.2 | Advisory | Generic justification, is useful when designing C library.            |
|  Rule 21.6 | Required | Include only in debug                                                 |


# Dependencies

- MicroEJ Architecture `7.x` or higher.
- WolfSSL 5.7.x

# Source

N/A

# Restrictions

None.

---
_Copyright 2025 MicroEJ Corp. All rights reserved._
_Use of this source code is governed by a BSD-style license that can be found with this software._
