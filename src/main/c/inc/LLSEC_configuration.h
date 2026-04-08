/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY WolfCrypt - Configuration.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

#ifndef LLSEC_CONFIGURATION_H
#define LLSEC_CONFIGURATION_H

#if __has_include(<veeport_configuration.h>)
  #include <veeport_configuration.h>
#endif

// Dynamic Allocators

/**
 * @brief Sets the dynamic allocation function used by both wolfSSL and this Abstraction Layer. Default is calloc.
 */
#ifndef LLSEC_CALLOC_IMPL
#define LLSEC_CALLOC_IMPL(x, y)                  calloc((x) * (y))
#endif

/**
 * @brief Sets the dynamic deallocation function used by both wolfSSL and this Abstraction Layer. Default is free.
 */
#ifndef LLSEC_FREE_IMPL
#define LLSEC_FREE_IMPL(x)                       free((x))
#endif

// Async Worker for long blocking crypto operations

#ifndef LLSEC_WORKER_PRIORITY
#define LLSEC_WORKER_PRIORITY                     (2)
#endif
#ifndef LLSEC_WORKER_STACK_SIZE
#define LLSEC_WORKER_STACK_SIZE                   (4096)
#endif
#ifndef LLSEC_WORKER_JOB_COUNT
#define LLSEC_WORKER_JOB_COUNT                    (2)
#endif
#ifndef LLSEC_WAITING_LIST_SIZE
#define LLSEC_WAITING_LIST_SIZE                   (4)
#endif

// Static configuration

#ifndef LLSEC_KEY_AGREEMENT_MAX_SECRET_SIZE
#define LLSEC_KEY_AGREEMENT_MAX_SECRET_SIZE       (1024)
#endif

#ifndef LLSEC_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH
#define LLSEC_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH             (32)
#endif

#ifndef LLSEC_EXTERNAL_KEYSTORE_PASSWORD_MAX_LENGTH
#define LLSEC_EXTERNAL_KEYSTORE_PASSWORD_MAX_LENGTH          (32)
#endif

/**
 * @brief Sets the maximum size of the data in bytes that can be retrieved from a Key Store entry
 */
#ifndef LLSEC_EXTERNAL_KEYSTORE_CERTIFICATE_MAX_BYTES
#define LLSEC_EXTERNAL_KEYSTORE_CERTIFICATE_MAX_BYTES 1024
#endif

// Enable local asserts by redirecting to the BSP's assert macro

#ifndef LLSEC_ASSERT
#define LLSEC_ASSERT(x)                           ((void)(x))
#endif

// Debug traces activation

#define LLSEC_DEBUG_TRACE_ENABLE                  (1)
#define LLSEC_DEBUG_TRACE_DISABLE                 (0)

#ifndef LLSEC_DEBUG_TRACE
// cppcheck-suppress [misra-c2012-21.6] : Include only in debug
#include <stdio.h>
/**
 * @brief Sets the redirection of log printing from the LLSECURITY native code. Default is printf.
 */
#define LLSEC_DEBUG_TRACE(...)                    printf("[LLSEC] "); printf(__VA_ARGS__);
#endif
#ifndef LLSEC_ALL_DEBUG
#define LLSEC_ALL_DEBUG                           LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_GENERIC_DEBUG
#define LLSEC_GENERIC_DEBUG                       LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_CIPHER_DEBUG
#define LLSEC_CIPHER_DEBUG                        LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_DIGEST_DEBUG
#define LLSEC_DIGEST_DEBUG                        LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_EXTERNAL_KEYSTORE_DEBUG
#define LLSEC_EXTERNAL_KEYSTORE_DEBUG             LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_KEY_FACTORY_DEBUG
#define LLSEC_KEY_FACTORY_DEBUG                   LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_KEY_PAIR_GENERATOR_DEBUG
#define LLSEC_KEY_PAIR_GENERATOR_DEBUG            LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_MAC_DEBUG
#define LLSEC_MAC_DEBUG                           LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_PRIVATE_KEY_DEBUG
#define LLSEC_PRIVATE_KEY_DEBUG                   LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_PUBLIC_KEY_DEBUG
#define LLSEC_PUBLIC_KEY_DEBUG                    LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_RANDOM_DEBUG
#define LLSEC_RANDOM_DEBUG                        LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_RSA_CIPHER_DEBUG
#define LLSEC_RSA_CIPHER_DEBUG                    LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_SECRET_KEY_FACTORY_DEBUG
#define LLSEC_SECRET_KEY_FACTORY_DEBUG            LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_SECRET_KEY_DEBUG
#define LLSEC_SECRET_KEY_DEBUG                     LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_SIG_DEBUG
#define LLSEC_SIG_DEBUG                            LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_X509_DEBUG
#define LLSEC_X509_DEBUG                           LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_CERT_PATH_VALIDATOR_DEBUG
#define LLSEC_CERT_PATH_VALIDATOR_DEBUG            LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_KEY_AGREEMENT_DEBUG
#define LLSEC_KEY_AGREEMENT_DEBUG                  LLSEC_DEBUG_TRACE_DISABLE
#endif

#if (LLSEC_GENERIC_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_GENERIC_DEBUG_TRACE(...)              LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_GENERIC_DEBUG_TRACE(...)              ((void)(0))
#endif

#if (LLSEC_CIPHER_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_CIPHER_DEBUG_TRACE(...)              LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_CIPHER_DEBUG_TRACE(...)              ((void)(0))
#endif

#if (LLSEC_DIGEST_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_DIGEST_DEBUG_TRACE(...)              LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_DIGEST_DEBUG_TRACE(...)              ((void)(0))
#endif

#if (LLSEC_EXTERNAL_KEYSTORE_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_EXTERNAL_KEYSTORE_DEBUG_TRACE(...)   LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_EXTERNAL_KEYSTORE_DEBUG_TRACE(...)   ((void)(0))
#endif

#if (LLSEC_KEY_FACTORY_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_KEY_FACTORY_DEBUG_TRACE(...)         LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_KEY_FACTORY_DEBUG_TRACE(...)         ((void)(0))
#endif

#if (LLSEC_KEY_PAIR_GENERATOR_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE(...)  LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE(...)  ((void)(0))
#endif

#if (LLSEC_MAC_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_MAC_DEBUG_TRACE(...)                 LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_MAC_DEBUG_TRACE(...)                 ((void)(0))
#endif

#if (LLSEC_PRIVATE_KEY_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_PRIVATE_KEY_DEBUG_TRACE(...)         LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_PRIVATE_KEY_DEBUG_TRACE(...)         ((void)(0))
#endif

#if (LLSEC_PUBLIC_KEY_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_PUBLIC_KEY_DEBUG_TRACE(...)          LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_PUBLIC_KEY_DEBUG_TRACE(...)          ((void)(0))
#endif

#if (LLSEC_RANDOM_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_RANDOM_DEBUG_TRACE(...)              LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_RANDOM_DEBUG_TRACE(...)              ((void)(0))
#endif

#if (LLSEC_RSA_CIPHER_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_RSA_CIPHER_DEBUG_TRACE(...)          LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_RSA_CIPHER_DEBUG_TRACE(...)          ((void)(0))
#endif

#if (LLSEC_SECRET_KEY_FACTORY_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE(...)  LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE(...)  ((void)(0))
#endif

#if (LLSEC_SECRET_KEY_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_SECRET_KEY_DEBUG_TRACE(...)          LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_SECRET_KEY_DEBUG_TRACE(...)          ((void)(0))
#endif

#if (LLSEC_SIG_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_SIG_DEBUG_TRACE(...)                 LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_SIG_DEBUG_TRACE(...)                 ((void)(0))
#endif

#if (LLSEC_X509_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_X509_DEBUG_TRACE(...)                LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_X509_DEBUG_TRACE(...)                ((void)(0))
#endif

#if (LLSEC_CERT_PATH_VALIDATOR_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE(...) LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE(...) ((void)(0))
#endif

#if (LLSEC_KEY_AGREEMENT_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_KEY_AGREEMENT_DEBUG_TRACE(...) LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_KEY_AGREEMENT_DEBUG_TRACE(...) ((void)(0))
#endif

#endif // LLSEC_CONFIGURATION_H

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
