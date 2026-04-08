/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY WolfCrypt - Common.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

#ifndef LLSEC_COMMON_H
#define LLSEC_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

// -----------------------------------------------------------------------------
// Includes
// -----------------------------------------------------------------------------

#include <LLSEC_wolfcrypt.h>
#include <LLSEC_configuration.h>
#include "microej_async_worker.h"

// -----------------------------------------------------------------------------
// Macros and defines
// -----------------------------------------------------------------------------

#define LLSEC_SUCCESS                             (0)
#define LLSEC_ERROR                               (-1)
#define LLSEC_ERROR_OOM                           (-2)
#define LLSEC_ERROR_EXCEPTION                     (-3)
#define LLSEC_ERROR_NO_JOB                        (-4)
#define LLSEC_ERROR_NOT_COMPLETED                 (-5)

#define LLSEC_UNUSED_PARAM(x)                     ((void)(x))

// -----------------------------------------------------------------------------
// Globals
// -----------------------------------------------------------------------------

// Async worker
extern MICROEJ_ASYNC_WORKER_handle_t llsec_worker;

// -----------------------------------------------------------------------------
// Wrapper functions
// -----------------------------------------------------------------------------

void llsec_memcpy(void *destination, const void *source, size_t num);
void llsec_strncpy(uint8_t *destination, const char *source, size_t num);
void * llsec_calloc(size_t num, size_t size);
void llsec_free(void *ptr);
void llsec_throw(int32_t errorCode, const char *message);
MICROEJ_ASYNC_WORKER_job_t * llsec_allocate_job(SNI_callback retry_callback);
int32_t llsec_async_exec(MICROEJ_ASYNC_WORKER_job_t *job, MICROEJ_ASYNC_WORKER_action_t action,
                         SNI_callback on_done_callback);
void llsec_free_job(MICROEJ_ASYNC_WORKER_job_t *job);

/**
 * @brief Provides the static Heap array pointer used by wolfSSL and the LLSEC Abstraction Layer.
 *
 * The default implementation of this function can be overridden; the weak function
 * implmentation returns NULL to use the system heap by default.
 *
 * @return The Static Heap array pointer if a custom heap is used, NULL if the system heap is used.
 *
 * @note Update the definition of <code>LLSEC_CALLOC_IMPL</code> and <code>LLSEC_FREE_IMPL</code> when a custom heap
 * is used.
 */
WOLFSSL_HEAP_HINT * llsec_wolfssl_get_heap(void);

// -----------------------------------------------------------------------------
// Typedef and Structure
// -----------------------------------------------------------------------------

// Forward declaration of types referred only by pointer in the async worker structures
// This is preferable as the only requirement in this header is to calculate the size of
// the union.
typedef struct LLSEC_KEY_PAIR_GENERATOR_algorithm LLSEC_KEY_PAIR_GENERATOR_algorithm;
typedef struct LLSEC_SIG_algorithm LLSEC_SIG_algorithm;
typedef struct LLSEC_CPV LLSEC_CPV;

typedef struct {
	LLSEC_key_pair *key;
	const LLSEC_KEY_PAIR_GENERATOR_algorithm *algorithm;
	int32_t rsa_key_size;
	int32_t rsa_public_exponent;
	char *ec_curve_stdname;
	int rc;
	int wolfcrypt_rc;
	const char *reason;
	char ec_curve_stdname_buffer[LLSEC_MAX_EC_CURVE_NAME_LEN];
} LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_params_t;

typedef struct {
	LLSEC_SIG_algorithm *algorithm;
	uint8_t *signature;
	int32_t signature_length;
	LLSEC_priv_key *private_key;
	uint8_t *digest;
	int32_t digest_length;
	int rc;
	int error_code;
	const char *reason;
} LLSEC_SIG_sign_params_t;

typedef struct {
	LLSEC_SIG_algorithm *algorithm;
	uint8_t *signature;
	int32_t signature_length;
	LLSEC_pub_key *public_key;
	uint8_t *digest;
	int32_t digest_length;
	int rc;
	int error_code;
	const char *reason;
} LLSEC_SIG_verify_params_t;

typedef struct {
	LLSEC_CPV *cpv;
	uint8_t *x509;
	int32_t x509_length;
	int32_t format;
	int32_t rc;
} LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t;

typedef struct {
	LLSEC_priv_key *priv_key;
	LLSEC_pub_key *pub_key;
	uint8_t secret_buffer[LLSEC_KEY_AGREEMENT_MAX_SECRET_SIZE];
	int32_t secret_size;
	int32_t rc;
	int wolfcrypt_rc;
} LLSEC_KEY_AGREEMENT_generate_secret_params_t;

/**
 * @brief Data structure to get the key ID in the external keystore.
 *
 * This structure is used by <code>LLSEC_EXTERNAL_KEYSTORE_IMPL_getKeyId</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jbyte alias[LLSEC_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH]; /*!< [IN] String of the alias of the target keystore entry.
	                                                        */
	jchar password[LLSEC_EXTERNAL_KEYSTORE_PASSWORD_MAX_LENGTH]; /*!< [IN] String of the password of the target keystore
	                                                              * entry. */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLSEC_EXTERNAL_KEYSTORE_get_key_id_params_t;

/**
 * @brief Data structure to get the key alias in the external keystore.
 *
 * This structure is used by <code>LLSEC_EXTERNAL_KEYSTORE_IMPL_getAlias</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jint index; /*!< [IN] Index of the target entry in the keystore. */
	jbyte alias[LLSEC_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH]; /*!< [OUT] Output array to contain the alias of the keystore
	                                                        * entry. */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLSEC_EXTERNAL_KEYSTORE_get_alias_params_t;

/**
 * @brief Data structure to check if the given alias is in the external keystore.
 *
 * This structure is used by <code>LLSEC_EXTERNAL_KEYSTORE_IMPL_containsAlias</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jbyte alias[LLSEC_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH]; /*!< [IN] Array containing the alias to search. */
	bool result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLSEC_EXTERNAL_KEYSTORE_contains_alias_params_t;

/**
 * @brief Data structure to get the Certificate handle from the external keystore.
 *
 * This structure is used by <code>LLSEC_EXTERNAL_KEYSTORE_IMPL_getCertificateHandle</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jbyte alias[LLSEC_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH]; /*!< [IN] Array containing the certificate alias to search.
	                                                        */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLSEC_EXTERNAL_KEYSTORE_get_certificate_handle_params_t;

/**
 * @brief Data structure to get the size of the given certificate in the external keystore.
 *
 * This structure is used by <code>LLSEC_EXTERNAL_KEYSTORE_IMPL_getCertificateSize</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jint cert_handle;/*!< [IN] Certificate handle from the external keystore. */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLSEC_EXTERNAL_KEYSTORE_get_certificate_size_params_t;

/**
 * @brief Data structure to get the data of the given certificate in the external keystore.
 *
 * This structure is used by <code>LLSEC_EXTERNAL_KEYSTORE_IMPL_getCertificateData</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jint cert_handle;/*!< [IN] Certificate handle from the external keystore. */
	uint8_t buffer[LLSEC_EXTERNAL_KEYSTORE_CERTIFICATE_MAX_BYTES]; /*!< [OUT] The certificate data of the keystore. */
	uint32_t cert_size; /*!< [OUT] Size of certificate stored in the output buffer. */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLSEC_EXTERNAL_KEYSTORE_get_certificate_data_params_t;

/**
 * @brief Data structure to get the certificate chain handle from the external keystore.
 *
 * This structure is used by <code>LLSEC_EXTERNAL_KEYSTORE_IMPL_getCertificateChainHandle</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jbyte alias[LLSEC_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH]; /*!< [IN] Array containing the certificate alias to search.
	                                                        */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLSEC_EXTERNAL_KEYSTORE_get_certificate_chain_handle_params_t;

/**
 * @brief Data structure to build an EC public key from raw parameters.
 *
 * This structure is used by <code>LLSEC_KEY_FACTORY_IMPL_get_ec_public_key_from_raw</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	uint8_t curve_name[LLSEC_MAX_EC_CURVE_NAME_LEN]; /*!< [IN] Name of the curve. */
	uint8_t x[LLSEC_MAX_EC_CURVE_POINT_SIZE]; /*!< [IN] x parameter of the curve. */
	uint8_t y[LLSEC_MAX_EC_CURVE_POINT_SIZE]; /*!< [IN] y parameter of the curve. */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
} LLSEC_KEY_FACTORY_ec_public_key_from_raw_params_t;

/**
 * @brief Data structure to encode a private key.
 *
 * This structure is used by <code>LLSEC_PRIVATE_KEY_IMPL_get_encode</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>error_code</code> field corresponds to the value returned by it.
 */
typedef struct {
	LLSEC_priv_key *key; /*!< [IN] Pointer to the key structure */
	uint8_t *output; /*!< [OUT] Encoded key. */
	int32_t output_length; /*!< [IN] The length of the output array. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
} LLSEC_PRIVATE_KEY_get_encoded_params_t;

typedef union {
	LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_params_t KEY_PAIR_GENERATOR_generateKeyPair;
	LLSEC_SIG_sign_params_t SIG_sign;
	LLSEC_SIG_verify_params_t SIG_verify;
	LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t CPV_verify;
	LLSEC_KEY_AGREEMENT_generate_secret_params_t KA_generate_secret;
	LLSEC_KEY_FACTORY_ec_public_key_from_raw_params_t KEY_FACTORY_ecPubKeyFromRaw;
	LLSEC_PRIVATE_KEY_get_encoded_params_t PRIVATE_KEY_getEncoded;
	LLSEC_EXTERNAL_KEYSTORE_get_key_id_params_t PKCS11_get_key_id;
	LLSEC_EXTERNAL_KEYSTORE_get_alias_params_t PKCS11_get_alias;
	LLSEC_EXTERNAL_KEYSTORE_contains_alias_params_t LLSEC_EXTERNAL_KEYSTORE_contains_alias;
	LLSEC_EXTERNAL_KEYSTORE_get_certificate_handle_params_t LLSEC_EXTERNAL_KEYSTORE_get_certificate_handle;
	LLSEC_EXTERNAL_KEYSTORE_get_certificate_size_params_t LLSEC_EXTERNAL_KEYSTORE_get_certificate_size;
	LLSEC_EXTERNAL_KEYSTORE_get_certificate_data_params_t LLSEC_EXTERNAL_KEYSTORE_get_certificate_data;
	LLSEC_EXTERNAL_KEYSTORE_get_certificate_chain_handle_params_t LLSEC_EXTERNAL_KEYSTORE_get_certificate_chain_handle;
} LLSEC_worker_params_t;

#ifdef __cplusplus
}
#endif

#endif // LLSEC_COMMON_H

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
