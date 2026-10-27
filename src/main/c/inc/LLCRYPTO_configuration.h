/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO WolfCrypt - Configuration.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

#ifndef LLCRYPTO_CONFIGURATION_H
#define LLCRYPTO_CONFIGURATION_H

#if __has_include(<veeport_configuration.h>)
  #include <veeport_configuration.h>
#endif

// Dynamic Allocators

/**
 * @brief Sets the dynamic allocation function used by both wolfSSL and this Abstraction Layer. Default is calloc.
 */
#ifndef LLCRYPTO_CALLOC_IMPL
#define LLCRYPTO_CALLOC_IMPL(x, y)                  calloc((x), (y))
#endif

/**
 * @brief Sets the dynamic deallocation function used by both wolfSSL and this Abstraction Layer. Default is free.
 */
#ifndef LLCRYPTO_FREE_IMPL
#define LLCRYPTO_FREE_IMPL(x)                       free((x))
#endif

// Async Worker for long blocking crypto operations

#ifndef LLCRYPTO_WORKER_PRIORITY
#define LLCRYPTO_WORKER_PRIORITY                     (2)
#endif
#ifndef LLCRYPTO_WORKER_STACK_SIZE
#define LLCRYPTO_WORKER_STACK_SIZE                   (4096)
#endif
#ifndef LLCRYPTO_WORKER_JOB_COUNT
#define LLCRYPTO_WORKER_JOB_COUNT                    (2)
#endif
#ifndef LLCRYPTO_WAITING_LIST_SIZE
#define LLCRYPTO_WAITING_LIST_SIZE                   (4)
#endif

/**
 * @brief Hook invoked once the async worker task has been created, with the MICROEJ_ASYNC_WORKER_handle_t worker as
 * argument. A VEE Port can override it in veeport_configuration.h to apply platform-specific settings to the worker
 * task (for example, allocate a TrustZone secure stack to it). Default is no operation.
 */
#ifndef LLCRYPTO_WORKER_POST_INIT_HOOK
#define LLCRYPTO_WORKER_POST_INIT_HOOK(worker)       ((void)(worker))
#endif

// Static configuration

#ifndef LLCRYPTO_KEY_AGREEMENT_MAX_SECRET_SIZE
#define LLCRYPTO_KEY_AGREEMENT_MAX_SECRET_SIZE       (1024)
#endif

#ifndef LLCRYPTO_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH
#define LLCRYPTO_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH             (32)
#endif

#ifndef LLCRYPTO_EXTERNAL_KEYSTORE_PASSWORD_MAX_LENGTH
#define LLCRYPTO_EXTERNAL_KEYSTORE_PASSWORD_MAX_LENGTH          (32)
#endif

/**
 * @brief Sets the maximum size of the data in bytes that can be retrieved from a Key Store entry
 */
#ifndef LLCRYPTO_EXTERNAL_KEYSTORE_CERTIFICATE_MAX_BYTES
#define LLCRYPTO_EXTERNAL_KEYSTORE_CERTIFICATE_MAX_BYTES 1024
#endif

// Enable local asserts by redirecting to the BSP's assert macro

#ifndef LLCRYPTO_ASSERT
#define LLCRYPTO_ASSERT(x)                           ((void)(x))
#endif

// Debug traces activation

#define LLCRYPTO_DEBUG_TRACE_ENABLE                  (1)
#define LLCRYPTO_DEBUG_TRACE_DISABLE                 (0)

#ifndef LLCRYPTO_DEBUG_TRACE
// cppcheck-suppress [misra-c2012-21.6] : Include only in debug
#include <stdio.h>
/**
 * @brief Sets the redirection of log printing from the LLCRYPTO native code. Default is printf.
 */
#define LLCRYPTO_DEBUG_TRACE(...)                    printf("[LLCRYPTO] "); printf(__VA_ARGS__);
#endif
#ifndef LLCRYPTO_ALL_DEBUG
#define LLCRYPTO_ALL_DEBUG                           LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_GENERIC_DEBUG
#define LLCRYPTO_GENERIC_DEBUG                       LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_CIPHER_DEBUG
#define LLCRYPTO_CIPHER_DEBUG                        LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_DIGEST_DEBUG
#define LLCRYPTO_DIGEST_DEBUG                        LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_EXTERNAL_KEYSTORE_DEBUG
#define LLCRYPTO_EXTERNAL_KEYSTORE_DEBUG             LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_KEY_FACTORY_DEBUG
#define LLCRYPTO_KEY_FACTORY_DEBUG                   LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_KEY_PAIR_GENERATOR_DEBUG
#define LLCRYPTO_KEY_PAIR_GENERATOR_DEBUG            LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_MAC_DEBUG
#define LLCRYPTO_MAC_DEBUG                           LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_PRIVATE_KEY_DEBUG
#define LLCRYPTO_PRIVATE_KEY_DEBUG                   LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_PUBLIC_KEY_DEBUG
#define LLCRYPTO_PUBLIC_KEY_DEBUG                    LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_RANDOM_DEBUG
#define LLCRYPTO_RANDOM_DEBUG                        LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_RSA_CIPHER_DEBUG
#define LLCRYPTO_RSA_CIPHER_DEBUG                    LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_SECRET_KEY_FACTORY_DEBUG
#define LLCRYPTO_SECRET_KEY_FACTORY_DEBUG            LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_SECRET_KEY_DEBUG
#define LLCRYPTO_SECRET_KEY_DEBUG                     LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_SIG_DEBUG
#define LLCRYPTO_SIG_DEBUG                            LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_X509_DEBUG
#define LLCRYPTO_X509_DEBUG                           LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG
#define LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG            LLCRYPTO_DEBUG_TRACE_DISABLE
#endif
#ifndef LLCRYPTO_KEY_AGREEMENT_DEBUG
#define LLCRYPTO_KEY_AGREEMENT_DEBUG                  LLCRYPTO_DEBUG_TRACE_DISABLE
#endif

#if (LLCRYPTO_GENERIC_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_GENERIC_DEBUG_TRACE(...)              LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_GENERIC_DEBUG_TRACE(...)              ((void)(0))
#endif

#if (LLCRYPTO_CIPHER_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_CIPHER_DEBUG_TRACE(...)              LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_CIPHER_DEBUG_TRACE(...)              ((void)(0))
#endif

#if (LLCRYPTO_DIGEST_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_DIGEST_DEBUG_TRACE(...)              LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_DIGEST_DEBUG_TRACE(...)              ((void)(0))
#endif

#if (LLCRYPTO_EXTERNAL_KEYSTORE_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || \
	 LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_EXTERNAL_KEYSTORE_DEBUG_TRACE(...)   LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_EXTERNAL_KEYSTORE_DEBUG_TRACE(...)   ((void)(0))
#endif

#if (LLCRYPTO_KEY_FACTORY_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_KEY_FACTORY_DEBUG_TRACE(...)         LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_KEY_FACTORY_DEBUG_TRACE(...)         ((void)(0))
#endif

#if (LLCRYPTO_KEY_PAIR_GENERATOR_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || \
	 LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_KEY_PAIR_GENERATOR_DEBUG_TRACE(...)  LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_KEY_PAIR_GENERATOR_DEBUG_TRACE(...)  ((void)(0))
#endif

#if (LLCRYPTO_MAC_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_MAC_DEBUG_TRACE(...)                 LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_MAC_DEBUG_TRACE(...)                 ((void)(0))
#endif

#if (LLCRYPTO_PRIVATE_KEY_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE(...)         LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE(...)         ((void)(0))
#endif

#if (LLCRYPTO_PUBLIC_KEY_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_PUBLIC_KEY_DEBUG_TRACE(...)          LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_PUBLIC_KEY_DEBUG_TRACE(...)          ((void)(0))
#endif

#if (LLCRYPTO_RANDOM_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_RANDOM_DEBUG_TRACE(...)              LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_RANDOM_DEBUG_TRACE(...)              ((void)(0))
#endif

#if (LLCRYPTO_RSA_CIPHER_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_RSA_CIPHER_DEBUG_TRACE(...)          LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_RSA_CIPHER_DEBUG_TRACE(...)          ((void)(0))
#endif

#if (LLCRYPTO_SECRET_KEY_FACTORY_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || \
	 LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE(...)  LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE(...)  ((void)(0))
#endif

#if (LLCRYPTO_SECRET_KEY_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_SECRET_KEY_DEBUG_TRACE(...)          LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_SECRET_KEY_DEBUG_TRACE(...)          ((void)(0))
#endif

#if (LLCRYPTO_SIG_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_SIG_DEBUG_TRACE(...)                 LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_SIG_DEBUG_TRACE(...)                 ((void)(0))
#endif

#if (LLCRYPTO_X509_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_X509_DEBUG_TRACE(...)                LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_X509_DEBUG_TRACE(...)                ((void)(0))
#endif

#if (LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || \
	 LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE(...) LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE(...) ((void)(0))
#endif

#if (LLCRYPTO_KEY_AGREEMENT_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE || LLCRYPTO_ALL_DEBUG == LLCRYPTO_DEBUG_TRACE_ENABLE)
#define LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE(...) LLCRYPTO_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE(...) ((void)(0))
#endif

#endif // LLCRYPTO_CONFIGURATION_H

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
