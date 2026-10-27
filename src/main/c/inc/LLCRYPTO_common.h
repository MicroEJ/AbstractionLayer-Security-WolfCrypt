/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO WolfCrypt - Common.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

#ifndef LLCRYPTO_COMMON_H
#define LLCRYPTO_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

// -----------------------------------------------------------------------------
// Includes
// -----------------------------------------------------------------------------

#include <LLCRYPTO_CONSTANTS.h>
#include <LLCRYPTO_wolfcrypt.h>
#include <LLCRYPTO_configuration.h>
#include "microej_async_worker.h"

// -----------------------------------------------------------------------------
// Macros and defines
// -----------------------------------------------------------------------------

/*
 * The codes returned to the Crypto library (LLCRYPTO_SUCCESS, LLCRYPTO_ERROR, LLCRYPTO_ERROR_OOM, ...) are the
 * ones of LLCRYPTO_CONSTANTS.h: this header does not define its own copy of them.
 *
 * The LLCRYPTO_JOB_* states below are private to the asynchronous worker jobs of this port. They never cross
 * the SNI boundary: a native returns a LLCRYPTO_CONSTANTS.h code (or SNI_IGNORED_RETURNED_VALUE) and reports a
 * job failure through llcrypto_throw(). Their values stay out of the LLCRYPTO_CONSTANTS.h range so that a state
 * leaking to the Crypto library cannot be misread as one of its error codes.
 */

/** The job action has not run yet: initial value of the job result. */
#define LLCRYPTO_JOB_NOT_COMPLETED                   (-100)

/** The job action failed: the job holds the error code and the reason of the NativeException to throw. */
#define LLCRYPTO_JOB_EXCEPTION                       (-101)

/** No job could be allocated: the Java thread is suspended until one is free, or a NativeException is pending. */
#define LLCRYPTO_JOB_UNAVAILABLE                     (-102)

#define LLCRYPTO_UNUSED_PARAM(x)                     ((void)(x))

// -----------------------------------------------------------------------------
// Globals
// -----------------------------------------------------------------------------

// Async worker
extern MICROEJ_ASYNC_WORKER_handle_t llcrypto_worker;

// -----------------------------------------------------------------------------
// Wrapper functions
// -----------------------------------------------------------------------------

void llcrypto_memcpy(void *destination, const void *source, size_t num);
void llcrypto_strncpy(uint8_t *destination, const char *source, size_t num);
void * llcrypto_calloc(size_t num, size_t size);
void llcrypto_free(void *ptr);
void llcrypto_throw(int32_t errorCode, const char *message);
MICROEJ_ASYNC_WORKER_job_t * llcrypto_allocate_job(SNI_callback retry_callback);
int32_t llcrypto_async_exec(MICROEJ_ASYNC_WORKER_job_t *job, MICROEJ_ASYNC_WORKER_action_t action,
                            SNI_callback on_done_callback);
void llcrypto_free_job(MICROEJ_ASYNC_WORKER_job_t *job);

/**
 * @brief Provides the static Heap array pointer used by wolfSSL and the LLCRYPTO Abstraction Layer.
 *
 * The default implementation of this function can be overridden; the weak function
 * implmentation returns NULL to use the system heap by default.
 *
 * @return The Static Heap array pointer if a custom heap is used, NULL if the system heap is used.
 *
 * @note Update the definition of <code>LLCRYPTO_CALLOC_IMPL</code> and <code>LLCRYPTO_FREE_IMPL</code> when a custom
 * heap
 * is used.
 */
WOLFSSL_HEAP_HINT * llcrypto_wolfssl_get_heap(void);

// -----------------------------------------------------------------------------
// Typedef and Structure
// -----------------------------------------------------------------------------

// Forward declaration of types referred only by pointer in the async worker structures
// This is preferable as the only requirement in this header is to calculate the size of
// the union.
typedef struct LLCRYPTO_KEY_PAIR_GENERATOR_algorithm LLCRYPTO_KEY_PAIR_GENERATOR_algorithm;
typedef struct LLCRYPTO_SIG_algorithm LLCRYPTO_SIG_algorithm;
typedef struct LLCRYPTO_CPV LLCRYPTO_CPV;

typedef struct {
	LLCRYPTO_key_pair *key;
	const LLCRYPTO_KEY_PAIR_GENERATOR_algorithm *algorithm;
	int32_t rsa_key_size;
	int32_t rsa_public_exponent;
	char *ec_curve_stdname;
	int rc;
	int wolfcrypt_rc;
	const char *reason;
	char ec_curve_stdname_buffer[LLCRYPTO_MAX_EC_CURVE_NAME_LEN];
} LLCRYPTO_KEY_PAIR_GENERATOR_generateKeyPair_params_t;

typedef struct {
	LLCRYPTO_SIG_algorithm *algorithm;
	uint8_t *signature;
	int32_t signature_length;
	LLCRYPTO_priv_key *private_key;
	uint8_t *digest;
	int32_t digest_length;
	int rc;
	int error_code;
	const char *reason;
} LLCRYPTO_SIG_sign_params_t;

typedef struct {
	LLCRYPTO_SIG_algorithm *algorithm;
	uint8_t *signature;
	int32_t signature_length;
	LLCRYPTO_pub_key *public_key;
	uint8_t *digest;
	int32_t digest_length;
	int rc;
	int error_code;
	const char *reason;
} LLCRYPTO_SIG_verify_params_t;

typedef struct {
	LLCRYPTO_CPV *cpv;
	uint8_t *x509;
	int32_t x509_length;
	int32_t format;
	int32_t rc;
} LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t;

typedef struct {
	LLCRYPTO_priv_key *priv_key;
	LLCRYPTO_pub_key *pub_key;
	uint8_t secret_buffer[LLCRYPTO_KEY_AGREEMENT_MAX_SECRET_SIZE];
	int32_t secret_size;
	int32_t rc;
	int wolfcrypt_rc;
} LLCRYPTO_KEY_AGREEMENT_generate_secret_params_t;

/**
 * @brief Data structure to get the key ID in the external keystore.
 *
 * This structure is used by <code>LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyId</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jbyte alias[LLCRYPTO_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH]; /*!< [IN] String of the alias of the target keystore
	                                                           * entry.
	                                                           */
	jchar password[LLCRYPTO_EXTERNAL_KEYSTORE_PASSWORD_MAX_LENGTH]; /*!< [IN] String of the password of the target
	                                                                 * keystore
	                                                                 * entry. */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLCRYPTO_EXTERNAL_KEYSTORE_get_key_id_params_t;

/**
 * @brief Data structure to get the key alias in the external keystore.
 *
 * This structure is used by <code>LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getAlias</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jint index; /*!< [IN] Index of the target entry in the keystore. */
	jbyte alias[LLCRYPTO_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH]; /*!< [OUT] Output array to contain the alias of the
	                                                           * keystore
	                                                           * entry. */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLCRYPTO_EXTERNAL_KEYSTORE_get_alias_params_t;

/**
 * @brief Data structure to check if the given alias is in the external keystore.
 *
 * This structure is used by <code>LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_containsAlias</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jbyte alias[LLCRYPTO_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH]; /*!< [IN] Array containing the alias to search. */
	bool result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLCRYPTO_EXTERNAL_KEYSTORE_contains_alias_params_t;

/**
 * @brief Data structure to get the Certificate handle from the external keystore.
 *
 * This structure is used by <code>LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateHandle</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jbyte alias[LLCRYPTO_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH]; /*!< [IN] Array containing the certificate alias to
	                                                           * search.
	                                                           */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_handle_params_t;

/**
 * @brief Data structure to get the size of the given certificate in the external keystore.
 *
 * This structure is used by <code>LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateSize</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jint cert_handle;/*!< [IN] Certificate handle from the external keystore. */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_size_params_t;

/**
 * @brief Data structure to get the data of the given certificate in the external keystore.
 *
 * This structure is used by <code>LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateData</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jint cert_handle;/*!< [IN] Certificate handle from the external keystore. */
	uint8_t buffer[LLCRYPTO_EXTERNAL_KEYSTORE_CERTIFICATE_MAX_BYTES]; /*!< [OUT] The certificate data of the keystore.
	                                                                   */
	uint32_t cert_size; /*!< [OUT] Size of certificate stored in the output buffer. */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_data_params_t;

/**
 * @brief Data structure to get the certificate chain handle from the external keystore.
 *
 * This structure is used by <code>LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChainHandle</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	jbyte alias[LLCRYPTO_EXTERNAL_KEYSTORE_ALIAS_MAX_LENGTH]; /*!< [IN] Array containing the certificate alias to
	                                                           * search.
	                                                           */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
	char *error_message; /*!< [OUT] Error message related to the error code. */
} LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_chain_handle_params_t;

/**
 * @brief Data structure to build an EC public key from raw parameters.
 *
 * This structure is used by <code>LLCRYPTO_KEY_FACTORY_IMPL_get_ec_public_key_from_raw</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>result</code> field corresponds to the value returned by it.
 */
typedef struct {
	uint8_t curve_name[LLCRYPTO_MAX_EC_CURVE_NAME_LEN]; /*!< [IN] Name of the curve. */
	uint8_t x[LLCRYPTO_MAX_EC_CURVE_POINT_SIZE]; /*!< [IN] x parameter of the curve. */
	uint8_t y[LLCRYPTO_MAX_EC_CURVE_POINT_SIZE]; /*!< [IN] y parameter of the curve. */
	int32_t result; /*!< [OUT] Result of the operation. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
} LLCRYPTO_KEY_FACTORY_ec_public_key_from_raw_params_t;

/**
 * @brief Data structure to encode a private key.
 *
 * This structure is used by <code>LLCRYPTO_PRIVATE_KEY_IMPL_get_encode</code>.
 *
 * Fields defined in this structure correspond to the parameters of this function, and
 * <code>error_code</code> field corresponds to the value returned by it.
 */
typedef struct {
	LLCRYPTO_priv_key *key; /*!< [IN] Pointer to the key structure */
	uint8_t *output; /*!< [OUT] Encoded key. */
	int32_t output_length; /*!< [IN] The length of the output array. */
	int32_t error_code; /*!< [OUT] Error code returned in case of error. */
} LLCRYPTO_PRIVATE_KEY_get_encoded_params_t;

typedef union {
	LLCRYPTO_KEY_PAIR_GENERATOR_generateKeyPair_params_t KEY_PAIR_GENERATOR_generateKeyPair;
	LLCRYPTO_SIG_sign_params_t SIG_sign;
	LLCRYPTO_SIG_verify_params_t SIG_verify;
	LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t CPV_verify;
	LLCRYPTO_KEY_AGREEMENT_generate_secret_params_t KA_generate_secret;
	LLCRYPTO_KEY_FACTORY_ec_public_key_from_raw_params_t KEY_FACTORY_ecPubKeyFromRaw;
	LLCRYPTO_PRIVATE_KEY_get_encoded_params_t PRIVATE_KEY_getEncoded;
	LLCRYPTO_EXTERNAL_KEYSTORE_get_key_id_params_t PKCS11_get_key_id;
	LLCRYPTO_EXTERNAL_KEYSTORE_get_alias_params_t PKCS11_get_alias;
	LLCRYPTO_EXTERNAL_KEYSTORE_contains_alias_params_t LLCRYPTO_EXTERNAL_KEYSTORE_contains_alias;
	LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_handle_params_t LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_handle;
	LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_size_params_t LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_size;
	LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_data_params_t LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_data;
	LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_chain_handle_params_t
	    LLCRYPTO_EXTERNAL_KEYSTORE_get_certificate_chain_handle;
} LLCRYPTO_worker_params_t;

#ifdef __cplusplus
}
#endif

#endif // LLCRYPTO_COMMON_H

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
