/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY WolfCrypt - Configuration.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

#ifndef LLSEC_CONFIGURATION_H
#define LLSEC_CONFIGURATION_H

// include MicroEJ User configuration file
#include <microej.h>
#if __has_include(<veeport_configuration.h>)
  #include <veeport_configuration.h>
#endif

// Debug traces activation

#define LLSEC_DEBUG_TRACE_ENABLE                  (1)
#define LLSEC_DEBUG_TRACE_DISABLE                 (0)

#ifndef LLSEC_DEBUG_TRACE
// cppcheck-suppress [misra-c2012-21.6] : Include only in debug
#include <stdio.h>
#define LLSEC_DEBUG_TRACE(...)                    printf("[LLSEC] "); printf(__VA_ARGS__);
#endif
#ifndef LLSEC_ALL_DEBUG
#define LLSEC_ALL_DEBUG                           LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_CIPHER_DEBUG
#define LLSEC_CIPHER_DEBUG                        LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_DIGEST_DEBUG
#define LLSEC_DIGEST_DEBUG                        LLSEC_DEBUG_TRACE_DISABLE
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
#define LLSEC_SECRET_KEY_DEBUG                    LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_SIG_DEBUG
#define LLSEC_SIG_DEBUG                           LLSEC_DEBUG_TRACE_DISABLE
#endif
#ifndef LLSEC_X509_DEBUG
#define LLSEC_X509_DEBUG                          LLSEC_DEBUG_TRACE_DISABLE
#endif

#if (LLSEC_CIPHER_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_CIPHER_DEBUG_TRACE(...)             LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_CIPHER_DEBUG_TRACE(...)             ((void)(0))
#endif

#if (LLSEC_DIGEST_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_DIGEST_DEBUG_TRACE(...)             LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_DIGEST_DEBUG_TRACE(...)             ((void)(0))
#endif

#if (LLSEC_KEY_FACTORY_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_KEY_FACTORY_DEBUG_TRACE(...)        LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_KEY_FACTORY_DEBUG_TRACE(...)        ((void)(0))
#endif

#if (LLSEC_KEY_PAIR_GENERATOR_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE(...) LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE(...) ((void)(0))
#endif

#if (LLSEC_MAC_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_MAC_DEBUG_TRACE(...)                LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_MAC_DEBUG_TRACE(...)                ((void)(0))
#endif

#if (LLSEC_PRIVATE_KEY_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_PRIVATE_KEY_DEBUG_TRACE(...)        LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_PRIVATE_KEY_DEBUG_TRACE(...)        ((void)(0))
#endif

#if (LLSEC_PUBLIC_KEY_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_PUBLIC_KEY_DEBUG_TRACE(...)         LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_PUBLIC_KEY_DEBUG_TRACE(...)         ((void)(0))
#endif

#if (LLSEC_RANDOM_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_RANDOM_DEBUG_TRACE(...)             LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_RANDOM_DEBUG_TRACE(...)             ((void)(0))
#endif

#if (LLSEC_RSA_CIPHER_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_RSA_CIPHER_DEBUG_TRACE(...)         LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_RSA_CIPHER_DEBUG_TRACE(...)         ((void)(0))
#endif

#if (LLSEC_SECRET_KEY_FACTORY_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE(...) LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE(...) ((void)(0))
#endif

#if (LLSEC_SECRET_KEY_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_SECRET_KEY_DEBUG_TRACE(...)         LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_SECRET_KEY_DEBUG_TRACE(...)         ((void)(0))
#endif

#if (LLSEC_SIG_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_SIG_DEBUG_TRACE(...)                LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_SIG_DEBUG_TRACE(...)                ((void)(0))
#endif

#if (LLSEC_X509_DEBUG == LLSEC_DEBUG_TRACE_ENABLE || LLSEC_ALL_DEBUG == LLSEC_DEBUG_TRACE_ENABLE)
#define LLSEC_X509_DEBUG_TRACE(...)               LLSEC_DEBUG_TRACE(__VA_ARGS__)
#else
#define LLSEC_X509_DEBUG_TRACE(...)               ((void)(0))
#endif

// -----------------------------------------------------------------------------
// Wolfcrypt specific macros and constants
// -----------------------------------------------------------------------------

// Defines the size of the seed generated when not specified by application.
#ifndef LLSEC_RANDOM_SEED_SIZE
  #define LLSEC_RANDOM_SEED_SIZE                    DRBG_SEED_LEN
#endif

/**
 * @brief default called function for dynamic allocation and initialization
 */
#ifndef LLSEC_calloc
  #define LLSEC_calloc                              calloc
#endif

/**
 * @brief default called function to free dynamic allocated objects
 */
#ifndef LLSEC_free
  #define LLSEC_free                                free
#endif

#endif // LLSEC_CONFIGURATION_H
