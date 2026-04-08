/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY WolfCrypt - common defines/functions/structs.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

#ifndef LLSEC_WOLFCRYPT_H
#define LLSEC_WOLFCRYPT_H

//#ifdef WOLFSSL_USER_SETTINGS
//#include <wolfssl/options.h>
//#else
//#endif // WOLFSSL_USER_SETTINGS
#include "wolfsslUserConfig.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_pkcs11.h>
#include <wolfssl/ssl.h>

#include <stdint.h>
#include <LLSEC_configuration.h>
#include <LLSEC_CONSTANTS.h>
#include <LLSEC_RSA_CIPHER_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup macros Macro and Constant definitions
 *
 *  @{
 */

#define LLSEC_MAX_EC_CURVE_NAME_LEN               ECC_MAXNAME

#define LLSEC_MAX_EC_CURVE_POINT_SIZE             (sizeof(mp_int))

#ifdef RSA_MAX_SIZE
#define LLSEC_MAX_PRIVATE_KEY_SIZE                (((ECC_MAXSIZE) > (RSA_MAX_SIZE))?(ECC_MAXSIZE):(RSA_MAX_SIZE))
#else
#define LLSEC_MAX_PRIVATE_KEY_SIZE                ECC_MAXSIZE
#endif

/**
 * @brief
 */
#define LLSEC_WOLFCRYPT_SUCCESS                   (0)

#define LLSEC_ERROR_OOM                           (-2)

/**
 * @brief
 */
#define LLSEC_X509_UNKNOWN_FORMAT                 ((int)(-1))

/**
 * @brief Defines the size of the seed generated when not specified by application.
 */
#ifndef LLSEC_RANDOM_SEED_SIZE
#define LLSEC_RANDOM_SEED_SIZE                    DRBG_SEED_LEN
#endif

/** @} */ // end of macros

/**
 * @brief Algorithm types
 * TODO: move to LLSEC_CONSTANTS.h
 */
typedef enum {
	ALGO_NONE  = 0,
	ALGO_RSA   = 16, // EVP_PKEY_RSA
	ALGO_ECDSA = 18, // EVP_PKEY_EC
	ALGO_AES   = 60, // Not part of evp.h enum, only need one type for AES
} LLSEC_algo_type;

/**
 * @brief Secret key description
 * TODO: move to LLSEC_CONSTANTS.h
 */
typedef struct {
	uint8_t *key;
	int32_t key_length;
} LLSEC_secret_key;

/**
 * @brief Generic key description
 */
typedef struct {
	LLSEC_algo_type algo_type;
	LLSEC_key_type key_type;
	union {
#ifndef NO_RSA
		RsaKey *rsa_key;
#endif // NO_RSA
#ifdef HAVE_ECC
		ecc_key *ec_key;
#endif // HAVE_ECC
		LLSEC_secret_key *secret_key;
		void *any_key; // to be used for either RsaKey* or ecc_key*
	};
} LLSEC_key;

typedef LLSEC_key LLSEC_priv_key;
typedef LLSEC_key LLSEC_pub_key;
typedef LLSEC_key LLSEC_key_pair;

extern WC_RNG *llsec_wolfcrypt_RNG;

/** @defgroup functions Wolfcrypt specific definitions
 *
 *  @{
 */

// See the .c file for the function documentation
char const * llsec_wc_error_message(int error_code);

// See the .c file for the function documentation
char *llsec_gen_random_str_internal(int length);

#ifndef NO_RSA
// See the .c file for the function documentation
enum wc_HashType llsec_rsa_get_wc_hash(int32_t hash);
#endif // NO_RSA

// See the .c file for the function documentation
enum wc_HashType llsec_sign_get_wc_hash_type(const uint8_t *stdname);

#ifndef NO_RSA
// See the .c file for the function documentation
int  llsec_rsa_get_padding(int32_t type);
#endif // NO_RSA

int32_t llsec_wolfcrypt_rsa_generate_key_pair(LLSEC_priv_key *key_pair, int32_t key_size,
                                              int32_t public_exponent, int *wolfcrypt_rc,
                                              const char **reason);
void llsec_wolfcrypt_rsa_free(LLSEC_priv_key *key);

// See the .c file for the function documentation
ecc_curve_id llsec_ecc_get_wc_curve_id(const uint8_t *stdname);

// See the .c file for the function documentation
int32_t get_x509_certificate_format(int8_t *cert_data, int32_t len, DecodedCert **cert_object,
                                    int32_t *check_error);

// See the .c file for the function documentation
void llsec_wolfcrypt_private_key_close(void *native_id);

#ifdef HAVE_ECC
// See the .c file for the function documentation
int32_t llsec_wolfcrypt_ec_init_label(char *label, LLSEC_key *key, int32_t device_id);

int32_t llsec_wolfcrypt_ec_generate_key_pair(LLSEC_priv_key *key_pair, uint8_t *curve_name,
                                             int *wolfcrypt_rc, const char **reason);
void llsec_wolfcrypt_ec_free(LLSEC_priv_key *key);

#endif

/** @} */ // end of functions

#ifdef __cplusplus
}
#endif

#endif /* LLSEC_WOLFCRYPT_H */

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
