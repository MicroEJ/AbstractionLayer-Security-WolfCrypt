/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO WolfCrypt - common defines/functions/structs.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 */

#ifndef LLCRYPTO_WOLFCRYPT_H
#define LLCRYPTO_WOLFCRYPT_H

/* settings.h pulls the wolfSSL configuration of the VEE Port: user_settings.h when WOLFSSL_USER_SETTINGS is
 * defined by the build, options.h otherwise. */
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
#ifdef HAVE_PKCS11
#include <wolfssl/wolfcrypt/wc_pkcs11.h>
#endif // HAVE_PKCS11
#include <wolfssl/ssl.h>

#include <stdint.h>
#include <LLCRYPTO_configuration.h>
#include <LLCRYPTO_CONSTANTS.h>
#include <LLCRYPTO_RSA_CIPHER_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup macros Macro and Constant definitions
 *
 *  @{
 */

#define LLCRYPTO_MAX_EC_CURVE_NAME_LEN               ECC_MAXNAME

#define LLCRYPTO_MAX_EC_CURVE_POINT_SIZE             (sizeof(mp_int))

#ifdef RSA_MAX_SIZE
#define LLCRYPTO_MAX_PRIVATE_KEY_SIZE                (((ECC_MAXSIZE) > (RSA_MAX_SIZE))?(ECC_MAXSIZE):(RSA_MAX_SIZE))
#else
#define LLCRYPTO_MAX_PRIVATE_KEY_SIZE                ECC_MAXSIZE
#endif

/**
 * @brief
 */
#define LLCRYPTO_WOLFCRYPT_SUCCESS                   (0)

/**
 * @brief
 */
#define LLCRYPTO_X509_UNKNOWN_FORMAT                 ((int)(-1))

/**
 * @brief Defines the size of the seed generated when not specified by application.
 */
#ifndef LLCRYPTO_RANDOM_SEED_SIZE
#define LLCRYPTO_RANDOM_SEED_SIZE                    DRBG_SEED_LEN
#endif

/** @} */ // end of macros

/**
 * @brief Algorithm types
 * TODO: move to LLCRYPTO_CONSTANTS.h
 */
typedef enum {
	ALGO_NONE  = 0,
	ALGO_RSA   = 16, // EVP_PKEY_RSA
	ALGO_ECDSA = 18, // EVP_PKEY_EC
	ALGO_AES   = 60, // Not part of evp.h enum, only need one type for AES
} LLCRYPTO_algo_type;

/**
 * @brief Secret key description.
 *
 * For raw-byte keys (e.g. from SecretKeySpec): key != NULL, key_length > 0,
 * label[0] == '\0', devId is unused.
 *
 * For PKCS#11 label-based keys (e.g. loaded from the external keystore):
 * key == NULL, key_length == 0, label holds the PKCS#11 object label,
 * devId is the WolfSSL crypto-callback device ID. These keys are only
 * available when wolfSSL is built with WOLF_PRIVATE_KEY_ID (implied by
 * HAVE_PKCS11 or WOLF_CRYPTO_CB).
 *
 * TODO: move to LLCRYPTO_CONSTANTS.h
 */
typedef struct {
	uint8_t *key;                    /**< Raw key bytes; NULL for PKCS#11 label-based keys. */
	int32_t key_length;              /**< Length in bytes of key; 0 for PKCS#11 label-based keys. */
#ifdef WOLF_PRIVATE_KEY_ID
	char label[AES_MAX_LABEL_LEN];  /**< PKCS#11 label; populated only when key == NULL. */
	int32_t devId;                   /**< WolfSSL devId for the PKCS#11 device; used only when key == NULL. */
#endif // WOLF_PRIVATE_KEY_ID
} LLCRYPTO_secret_key;

/**
 * @brief Generic key description
 */
typedef struct {
	LLCRYPTO_algo_type algo_type;
	LLCRYPTO_key_type key_type;
	union {
#ifndef NO_RSA
		RsaKey *rsa_key;
#endif // NO_RSA
#ifdef HAVE_ECC
		ecc_key *ec_key;
#endif // HAVE_ECC
		LLCRYPTO_secret_key *secret_key;
		void *any_key; // to be used for either RsaKey* or ecc_key*
	};
} LLCRYPTO_key;

typedef LLCRYPTO_key LLCRYPTO_priv_key;
typedef LLCRYPTO_key LLCRYPTO_pub_key;
typedef LLCRYPTO_key LLCRYPTO_key_pair;

extern WC_RNG *llcrypto_wolfcrypt_RNG;

/** @defgroup functions Wolfcrypt specific definitions
 *
 *  @{
 */

// See the .c file for the function documentation
char const * llcrypto_wc_error_message(int error_code);

// See the .c file for the function documentation
char *llcrypto_gen_random_str_internal(int length);

#ifndef NO_RSA
// See the .c file for the function documentation
enum wc_HashType llcrypto_rsa_get_wc_hash(int32_t hash);
#endif // NO_RSA

// See the .c file for the function documentation
enum wc_HashType llcrypto_sign_get_wc_hash_type(const uint8_t *stdname);

#ifndef NO_RSA
// See the .c file for the function documentation
int  llcrypto_rsa_get_padding(int32_t type);
#endif // NO_RSA

int32_t llcrypto_wolfcrypt_rsa_generate_key_pair(LLCRYPTO_priv_key *key_pair, int32_t key_size,
                                                 int32_t public_exponent, int *wolfcrypt_rc,
                                                 const char **reason);
void llcrypto_wolfcrypt_rsa_free(LLCRYPTO_priv_key *key);

// See the .c file for the function documentation
ecc_curve_id llcrypto_ecc_get_wc_curve_id(const uint8_t *stdname);

// See the .c file for the function documentation
int32_t get_x509_certificate_format(int8_t *cert_data, int32_t len, DecodedCert **cert_object,
                                    int32_t *check_error);

// See the .c file for the function documentation
void llcrypto_wolfcrypt_private_key_close(void *native_id);

#ifdef HAVE_ECC
#ifdef WOLF_PRIVATE_KEY_ID
// See the .c file for the function documentation
int32_t llcrypto_wolfcrypt_ec_init_label(char *label, LLCRYPTO_key *key, int32_t device_id);
#endif // WOLF_PRIVATE_KEY_ID

int32_t llcrypto_wolfcrypt_ec_generate_key_pair(LLCRYPTO_priv_key *key_pair, uint8_t *curve_name,
                                                int *wolfcrypt_rc, const char **reason);
void llcrypto_wolfcrypt_ec_free(LLCRYPTO_priv_key *key);

#endif

/** @} */ // end of functions

#ifdef __cplusplus
}
#endif

#endif /* LLCRYPTO_WOLFCRYPT_H */

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
