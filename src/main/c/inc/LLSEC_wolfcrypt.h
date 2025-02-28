/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY WolfCrypt - common defines/functions/structs.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

#ifndef LLSEC_WOLFCRYPT_H
#define LLSEC_WOLFCRYPT_H

#include <LLSEC_RSA_CIPHER_impl.h>
#include <LLSEC_configuration.h>

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/openssl/evp.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup checks Wolfcrypt configuration checks
 *  Minimum Requirements Checks in Wolfcrypt User Configuration
 *  @{
 */
#if WOLFSSL_SMALL_CERT_VERIFY != 1
  #error WOLFSSL_SMALL_CERT_VERIFY is required for the CRYPTO library to work properly
#endif

#if WOLF_CONF_MATH != 1
  #error  The WOLF_CONF_MATH value doesn't allow the CRYPTO library to work  properly
#endif

#if WOLF_CONF_RNG != 1
  #error WOLF_CONF_RNG is required for the CRYPTO library to work properly
#endif

#if WOLF_CONF_RSA != 1
  #error WOLF_CONF_RSA is required for the CRYPTO library to work properly
#endif

#if WOLF_CONF_ECC != 1
  #error WOLF_CONF_ECC is required for the CRYPTO library to work properly
#endif

#if WOLF_CONF_SHA2_256 != 1
  #error WOLF_CONF_SHA2_256 is required for the CRYPTO library to work properly
#endif

#ifndef WOLFSSL_KEY_GEN
  #error WOLFSSL_KEY_GEN is required for the CRYPTO library to work properly
#endif

#ifndef OPENSSL_EXTRA
  #error OPENSSL_EXTRA is required for the CRYPTO library to work properly
#endif

/** @} */ // end of checks

/** @defgroup macros Macro and Constant definitions
 *
 *  @{
 */

/**
 * @brief
 */
#define LLSEC_SUCCESS                             (0)

/**
 * @brief
 */
#define LLSEC_ERROR                               (-1)

/**
 * @brief
 */
#define LLSEC_WOLFCRYPT_SUCCESS                   (0)

/**
 * @brief
 */
#define LLSEC_UNUSED_PARAM(x)                     ((void)(x))

/** @} */ // end of macros



/**
 * @brief
 */
typedef enum {
	TYPE_RSA   = EVP_PKEY_RSA,
	TYPE_ECDSA = EVP_PKEY_EC,
} LLSEC_pub_key_type;

/**
 * @brief
 */
/*key must be an RsaKey or ecc_key TYPE*/
typedef struct {
	LLSEC_pub_key_type key_type;
	char *key;                  /* RsaKey or ecc_key */
} LLSEC_priv_key;

/**
 * @brief
 */
typedef struct {
	LLSEC_pub_key_type key_type;
	char *key;                  /* RsaKey or ecc_key */
} LLSEC_pub_key;

/**
 * @brief
 */
typedef struct {
	unsigned char *key;
	int32_t key_length;
} LLSEC_secret_key;

extern WC_RNG *llsec_wc_RNG;



/** @defgroup functions Wolfcrypt specific definitions
 *
 *  @{
 */

// See the .c file for the function documentation
int llsec_wc_initialize(void);

// See the .c file for the function documentation
char const * llsec_wc_error_message(int error_code);

// See the .c file for the function documentation
char *llsec_gen_random_str_internal(int length);

// See the .c file for the function documentation
enum wc_HashType llsec_rsa_get_wc_hash(LLSEC_RSA_CIPHER_oaep_hash_algorithm hash);

// See the .c file for the function documentation
enum wc_HashType llsec_sign_get_wc_hash_type(uint8_t *stdname);

// See the .c file for the function documentation
int  llsec_rsa_get_padding(LLSEC_RSA_CIPHER_padding_type type);

// See the .c file for the function documentation
ecc_curve_id llsec_ecc_get_wc_curve_id(uint8_t *stdname);

/** @} */ // end of functions

#ifdef __cplusplus
}
#endif

#endif /* LLSEC_WOLFCRYPT_H */
