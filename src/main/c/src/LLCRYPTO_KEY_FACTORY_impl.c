/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - Private & Public Key PKCS8 decoding.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_ERRORS.h>
#include <LLCRYPTO_KEY_FACTORY_impl.h>
#include <LLCRYPTO_wolfcrypt.h>
#include <LLCRYPTO_common.h>
#include "microej_async_worker.h"

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef int32_t (*LLCRYPTO_KEY_FACTORY_get_private_key_data)(LLCRYPTO_priv_key *priv_key, uint8_t *encoded_key,
                                                             int32_t encoded_key_length);
typedef int32_t (*LLCRYPTO_KEY_FACTORY_get_public_key_data)(LLCRYPTO_pub_key *pub_key, uint8_t *encoded_key,
                                                            int32_t encoded_key_length);
typedef void (*LLCRYPTO_KEY_FACTORY_key_close)(void *native_id);

typedef struct {
	char *name;
	LLCRYPTO_KEY_FACTORY_get_private_key_data get_private_key_data;
	LLCRYPTO_KEY_FACTORY_get_public_key_data get_public_key_data;
	LLCRYPTO_KEY_FACTORY_key_close private_key_close;
	LLCRYPTO_KEY_FACTORY_key_close public_key_close;
} LLCRYPTO_KEY_FACTORY_algorithm;

// --------------------------------------------------------------------------------
// Constant declarations
// --------------------------------------------------------------------------------

// cppcheck-suppress [misra-c2012-8.9] : Define here for code readability even if it called once in this file.
static const char *pkcs8_format = "PKCS#8";

// cppcheck-suppress [misra-c2012-8.9] : Define here for code readability even if it called once in this file.
static const char *x509_format = "X.509";

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

#ifndef NO_RSA
static int32_t LLCRYPTO_KEY_FACTORY_RSA_wolfcrypt_get_private_key_data(LLCRYPTO_priv_key *priv_key,
                                                                       uint8_t *encoded_key,
                                                                       int32_t encoded_key_length);
static int32_t LLCRYPTO_KEY_FACTORY_RSA_wolfcrypt_get_public_key_data(LLCRYPTO_pub_key *pub_key, uint8_t *encoded_key,
                                                                      int32_t encoded_key_length);
#endif // NO_RSA
static int32_t LLCRYPTO_KEY_FACTORY_EC_wolfcrypt_get_private_key_data(LLCRYPTO_priv_key *priv_key, uint8_t *encoded_key,
                                                                      int32_t encoded_key_length);
static int32_t LLCRYPTO_KEY_FACTORY_EC_wolfcrypt_get_public_key_data(LLCRYPTO_pub_key *pub_key, uint8_t *encoded_key,
                                                                     int32_t encoded_key_length);
static void LLCRYPTO_KEY_FACTORY_wolfcrypt_private_key_close(void *native_id);
static void LLCRYPTO_KEY_FACTORY_wolfcrypt_public_key_close(void *native_id);

// cppcheck-suppress [misra-c2012-8.9] : Define here for code readability even if it called once in this file.
static LLCRYPTO_KEY_FACTORY_algorithm available_key_algorithms[] = {
#ifndef NO_RSA
	{
		.name = "RSA",
		.get_private_key_data = LLCRYPTO_KEY_FACTORY_RSA_wolfcrypt_get_private_key_data,
		.get_public_key_data = LLCRYPTO_KEY_FACTORY_RSA_wolfcrypt_get_public_key_data,
		.private_key_close = llcrypto_wolfcrypt_private_key_close,
		.public_key_close = LLCRYPTO_KEY_FACTORY_wolfcrypt_public_key_close
	},
#endif // NO_RSA
	{
		.name = "EC",
		.get_private_key_data = LLCRYPTO_KEY_FACTORY_EC_wolfcrypt_get_private_key_data,
		.get_public_key_data = LLCRYPTO_KEY_FACTORY_EC_wolfcrypt_get_public_key_data,
		.private_key_close = llcrypto_wolfcrypt_private_key_close,
		.public_key_close = LLCRYPTO_KEY_FACTORY_wolfcrypt_public_key_close
	}
};

#ifndef NO_RSA
/**
 * @brief   Creates a Wolfcrypt RSA private key structure from a provided DER format the private key.
 *
 * @param[in]  priv_key  Pointer to the private key structure
 * @param[in]  encoded_key  Pointer to the buffer containing the DER encoded private key.
 * @param[in]  encoded_key_length  Size of the DER encoded private key.
 *
 * @return     LLCRYPTO_SUCCESS if the creation is successful,  LLCRYPTO_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t LLCRYPTO_KEY_FACTORY_RSA_wolfcrypt_get_private_key_data(LLCRYPTO_priv_key *priv_key,
                                                                       uint8_t *encoded_key,
                                                                       int32_t encoded_key_length) {
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (key = %p) \n", __func__, priv_key);
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("encLen %d, strlen: %zu, enc:%s  \n", (int)encoded_key_length,
	                                 strlen((char *)encoded_key), encoded_key);

	int return_code = LLCRYPTO_SUCCESS;
	int module_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	char *pers = NULL;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

	word32 idx = 0;

	priv_key->algo_type = ALGO_RSA;

	RsaKey *wolfcrypt_rsa_ctx;
	WC_RNG *wolfcrypt_rng_ctx;

	// RSA structure allocation
	wolfcrypt_rsa_ctx = llcrypto_calloc(1, sizeof(RsaKey)); //RSA key structure
	if (NULL == wolfcrypt_rsa_ctx) {
		return_code = LLCRYPTO_ERROR_OOM;
	} else {
		module_rc = wc_InitRsaKey(wolfcrypt_rsa_ctx, pHint);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != module_rc) {
			wc_FreeRsaKey(wolfcrypt_rsa_ctx);
			llcrypto_free(wolfcrypt_rsa_ctx);
			llcrypto_throw(module_rc, "RSA wolfcrypt init failed");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		pers = llcrypto_gen_random_str_internal(8);
		wolfcrypt_rng_ctx = wc_rng_new((byte *)pers, (word32)strlen(pers), pHint);
		if (NULL == wolfcrypt_rng_ctx) {
			llcrypto_throw(module_rc, "Failed to initialize random number generator for RSA");
			wc_rng_free(wolfcrypt_rng_ctx);

			llcrypto_free((void *)pers);
			return_code = LLCRYPTO_ERROR;
		} else {
			module_rc = wc_RsaSetRNG(wolfcrypt_rsa_ctx, wolfcrypt_rng_ctx);
			if (LLCRYPTO_WOLFCRYPT_SUCCESS != module_rc) {
				wc_FreeRsaKey(wolfcrypt_rsa_ctx);
				wc_rng_free(wolfcrypt_rng_ctx);
				llcrypto_free(wolfcrypt_rsa_ctx);
				llcrypto_throw(module_rc, "Failed to set random number generator for RSA Key Factory");
				return_code = LLCRYPTO_ERROR;
			}
		}
	}
	if (LLCRYPTO_SUCCESS == return_code) {
		module_rc = wc_RsaPrivateKeyDecode(encoded_key, &idx, wolfcrypt_rsa_ctx, encoded_key_length);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != module_rc) {
			LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("wc_RsaPrivateKeyDecode failed (rc = %d)", module_rc);
			return_code = LLCRYPTO_ERROR;
		} else {
			priv_key->rsa_key = wolfcrypt_rsa_ctx;
			if (NULL == priv_key->rsa_key) {
				llcrypto_throw(LLCRYPTO_ERROR, "RSA context extraction failed");
				return_code = LLCRYPTO_ERROR;
			}
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		void *native_id = (void *)priv_key;
		if (SNI_OK != SNI_registerResource(native_id, (SNI_closeFunction)llcrypto_wolfcrypt_private_key_close,
		                                   NULL)) {
			llcrypto_throw(LLCRYPTO_ERROR, "Can't register SNI native resource");
			wc_FreeRsaKey(priv_key->rsa_key);
			llcrypto_free(wolfcrypt_rsa_ctx);
			return_code = LLCRYPTO_ERROR;
		} else {
			// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
			return_code = (int32_t)native_id;
		}
	}

	if (NULL != pers) {
		llcrypto_free((void *)pers);
	}
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, return_code);
	return return_code;
}

/**
 * @brief   Creates a Wolfcrypt RSA public key structure from a provided DER format the public key.
 *
 * @param[in]  pub_key  Pointer to the public key structure
 * @param[in]  encoded_key  Pointer to the buffer containing the DER encoded public key.
 * @param[in]  encoded_key_length  Size of the DER encoded public key.
 *
 * @return     LLCRYPTO_SUCCESS if the creation is successful,  LLCRYPTO_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t LLCRYPTO_KEY_FACTORY_RSA_wolfcrypt_get_public_key_data(LLCRYPTO_pub_key *pub_key, uint8_t *encoded_key,
                                                                      int32_t encoded_key_length) {
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (key = %p) \n", __func__, pub_key);

	int return_code = LLCRYPTO_SUCCESS;
	int module_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;

	word32 idx = 0;

	pub_key->algo_type = ALGO_RSA;

	RsaKey *wolfcrypt_rsa_ctx;

	// RSA structure allocation
	wolfcrypt_rsa_ctx = llcrypto_calloc(1, sizeof(RsaKey)); //RSA key structure
	if (NULL == wolfcrypt_rsa_ctx) {
		return_code = LLCRYPTO_ERROR_OOM;
	} else {
		module_rc = wc_InitRsaKey(wolfcrypt_rsa_ctx, NULL);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != module_rc) {
			wc_FreeRsaKey(wolfcrypt_rsa_ctx);
			llcrypto_free(wolfcrypt_rsa_ctx);
			llcrypto_throw(module_rc, "RSA wolfcrypt init failed");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		module_rc = wc_RsaPublicKeyDecode(encoded_key, &idx, wolfcrypt_rsa_ctx, encoded_key_length);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != module_rc) {
			LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("wc_RsaPublicKeyDecode failed (rc = %d)", module_rc);
			wc_FreeRsaKey(wolfcrypt_rsa_ctx);
			llcrypto_free(wolfcrypt_rsa_ctx);
			return_code = LLCRYPTO_ERROR;
		} else {
			pub_key->rsa_key = wolfcrypt_rsa_ctx;
			if (NULL == pub_key->rsa_key) {
				llcrypto_throw(LLCRYPTO_ERROR, "RSA context extraction failed");
				return_code = LLCRYPTO_ERROR;
			}
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		void *native_id = (void *)pub_key;
		if (SNI_OK != SNI_registerResource(native_id,
		                                   (SNI_closeFunction)LLCRYPTO_KEY_FACTORY_wolfcrypt_public_key_close,
		                                   NULL)) {
			llcrypto_throw(LLCRYPTO_ERROR, "Can't register SNI native resource");
			wc_FreeRsaKey(pub_key->rsa_key);
			llcrypto_free(pub_key->rsa_key);
			return_code = LLCRYPTO_ERROR;
		} else {
			// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
			return_code = (int32_t)native_id;
		}
	}

	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, return_code);
	return return_code;
}

#endif // NO_RSA

/**
 * @brief Frees the resources and context associated of an Wolfcrypt private key structure.
 *
 * @param[in]  native_id  Pointer to  the Wolfcrypt private key structure.
 *
 */
void llcrypto_wolfcrypt_private_key_close(void *native_id) {
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_priv_key *key = (LLCRYPTO_priv_key *)native_id;

	if (NULL != key) {
#ifndef NO_RSA
		if ((ALGO_RSA == key->algo_type) && (NULL != key->rsa_key)) {
			wc_FreeRsaKey(key->rsa_key);
			llcrypto_free(key->rsa_key);
		}
#endif // NO_RSA
#ifdef HAVE_ECC
		if ((ALGO_ECDSA == key->algo_type) && (NULL != key->ec_key)) {
			wc_ecc_free(key->ec_key);
			llcrypto_free(key->ec_key);
		}
#endif // HAVE_ECC
		llcrypto_free(key);
	}
}

/**
 * @brief Frees the resources and context associated of an Wolfcrypt public key structure.
 *
 * @param[in]  native_id  Pointer to  the Wolfcrypt public key structure.
 *
 */
static void LLCRYPTO_KEY_FACTORY_wolfcrypt_public_key_close(void *native_id) {
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_pub_key *key = (LLCRYPTO_pub_key *)native_id;

	if (NULL != key) {
#ifndef NO_RSA
		if ((ALGO_RSA == key->algo_type) && (NULL != key->rsa_key)) {
			wc_FreeRsaKey(key->rsa_key);
			llcrypto_free(key->rsa_key);
		}
#endif // NO_RSA
#ifdef HAVE_ECC
		if ((ALGO_ECDSA == key->algo_type) && (NULL != key->ec_key)) {
			wc_ecc_free(key->ec_key);
			llcrypto_free(key->ec_key);
		}
#endif // HAVE_ECC
		llcrypto_free(key);
	}
}

/**
 * @brief   Creates a Wolfcrypt ECC private key structure from a provided DER format the private key.
 *
 * @param[in]  priv_key  Pointer to the private key structure
 * @param[in]  encoded_key  Pointer to the buffer containing the DER encoded private key.
 * @param[in]  encoded_key_length  Size of the DER encoded private key.
 *
 * @return     LLCRYPTO_SUCCESS if the creation is successful,  LLCRYPTO_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t LLCRYPTO_KEY_FACTORY_EC_wolfcrypt_get_private_key_data(LLCRYPTO_priv_key *priv_key, uint8_t *encoded_key,
                                                                      int32_t encoded_key_length) {
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (key = %p) \n", __func__, priv_key);
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("encLen %d, strlen: %zu, enc:%s  \n", (int)encoded_key_length,
	                                 strlen((char *)encoded_key), encoded_key);
	int return_code = LLCRYPTO_SUCCESS;
	char *pers = NULL;
	word32 idx = 0;

	priv_key->algo_type = ALGO_ECDSA;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

	int module_rc;
	ecc_key *wolfcrypt_ec_ctx;

	// EC structure allocation
	wolfcrypt_ec_ctx = (ecc_key *)llcrypto_calloc(1, sizeof(ecc_key)); //EC key structure
	if (NULL == wolfcrypt_ec_ctx) {
		return_code = LLCRYPTO_ERROR_OOM;
	} else {
		module_rc = wc_ecc_init_ex(wolfcrypt_ec_ctx, pHint, INVALID_DEVID);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != module_rc) {
			wc_ecc_free(wolfcrypt_ec_ctx);
			llcrypto_free(wolfcrypt_ec_ctx);
			llcrypto_throw(module_rc, "EC wolfcrypt init failed");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		module_rc = wc_EccPrivateKeyDecode(encoded_key, &idx, wolfcrypt_ec_ctx, encoded_key_length);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != module_rc) {
			LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("wc_EccPrivateKeyDecode failed (rc = %d)", module_rc);
			return_code = LLCRYPTO_ERROR;
		} else {
			priv_key->ec_key = wolfcrypt_ec_ctx;
			if (NULL == priv_key->ec_key) {
				llcrypto_throw(LLCRYPTO_ERROR, "EC context extraction failed");
				return_code = LLCRYPTO_ERROR;
			}
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		void *native_id = (void *)priv_key;
		if (SNI_OK != SNI_registerResource(native_id, (SNI_closeFunction)llcrypto_wolfcrypt_private_key_close,
		                                   NULL)) {
			llcrypto_throw(LLCRYPTO_ERROR, "Can't register SNI native resource");
			wc_ecc_free(priv_key->ec_key);
			llcrypto_free(wolfcrypt_ec_ctx);
			return_code = LLCRYPTO_ERROR;
		} else {
			// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
			return_code = (int32_t)native_id;
		}
	}

	if (NULL != pers) {
		llcrypto_free((void *)pers);
	}
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, return_code);
	return return_code;
}

/**
 * @brief   Creates a Wolfcrypt ECC public key structure from a provided DER format the public key.
 *
 * @param[in]  pub_key  Pointer to the public key structure
 * @param[in]  encoded_key  Pointer to the buffer containing the DER encoded public key.
 * @param[in]  encoded_key_length  Size of the DER encoded public key.
 *
 * @return     LLCRYPTO_SUCCESS if the creation is successful,  LLCRYPTO_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t LLCRYPTO_KEY_FACTORY_EC_wolfcrypt_get_public_key_data(LLCRYPTO_pub_key *pub_key, uint8_t *encoded_key,
                                                                     int32_t encoded_key_length) {
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (key = %p) \n", __func__, pub_key);

	int return_code = LLCRYPTO_SUCCESS;
	word32 idx = 0;
	pub_key->algo_type = ALGO_ECDSA;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

	int module_rc;
	ecc_key *wolfcrypt_ec_ctx;

	// EC structure allocation
	wolfcrypt_ec_ctx = (ecc_key *)llcrypto_calloc(1, sizeof(ecc_key)); //EC key structure
	if (NULL == wolfcrypt_ec_ctx) {
		return_code = LLCRYPTO_ERROR_OOM;
	} else {
		module_rc = wc_ecc_init_ex(wolfcrypt_ec_ctx, pHint, INVALID_DEVID);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != module_rc) {
			wc_ecc_free(wolfcrypt_ec_ctx);
			llcrypto_free(wolfcrypt_ec_ctx);
			llcrypto_throw(module_rc, "EC wolfcrypt init failed");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		module_rc = wc_EccPublicKeyDecode(encoded_key, &idx, wolfcrypt_ec_ctx, encoded_key_length);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != module_rc) {
			LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("wc_EccPublicKeyDecode failed (rc = %d)", module_rc);
			wc_ecc_free(wolfcrypt_ec_ctx);
			llcrypto_free(wolfcrypt_ec_ctx);
			return_code = LLCRYPTO_ERROR;
		} else {
			pub_key->ec_key = wolfcrypt_ec_ctx;
			if (NULL == pub_key->ec_key) {
				llcrypto_throw(LLCRYPTO_ERROR, "EC context extraction failed");
				return_code = LLCRYPTO_ERROR;
			}
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		void *native_id = (void *)pub_key;
		if (SNI_OK != SNI_registerResource(native_id,
		                                   (SNI_closeFunction)LLCRYPTO_KEY_FACTORY_wolfcrypt_public_key_close,
		                                   NULL)) {
			llcrypto_throw(LLCRYPTO_ERROR, "Can't register SNI native resource");
			wc_ecc_free(pub_key->ec_key);
			llcrypto_free(pub_key->ec_key);
			return_code = LLCRYPTO_ERROR;
		} else {
			// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
			return_code = (int32_t)native_id;
		}
	}

	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, return_code);
	return return_code;
}

// -----------------------------------------------------------------------------
// LLCRYPTO_KEY_FACTORY*_on_done functions
// -----------------------------------------------------------------------------

jint LLCRYPTO_KEY_FACTORY_IMPL_get_ec_public_key_from_raw_on_done(uint8_t *curveName, uint8_t *x, uint8_t *y) {
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s\n", __func__);
	MICROEJ_ASYNC_WORKER_job_t *job = MICROEJ_ASYNC_WORKER_get_job_done();
	LLCRYPTO_KEY_FACTORY_ec_public_key_from_raw_params_t *params =
		(LLCRYPTO_KEY_FACTORY_ec_public_key_from_raw_params_t *)job->params;

	// Parameters unused but mandatory to have the same signature than the original native.
	LLCRYPTO_UNUSED_PARAM(curveName);
	LLCRYPTO_UNUSED_PARAM(x);
	LLCRYPTO_UNUSED_PARAM(y);

	LLCRYPTO_pub_key *public_key = (LLCRYPTO_pub_key *)params->result;

	if (LLCRYPTO_SUCCESS == params->error_code) {
		if (SNI_OK != SNI_registerResource((void *)public_key,
		                                   (SNI_closeFunction)LLCRYPTO_KEY_FACTORY_wolfcrypt_public_key_close,
		                                   NULL)) {
			LLCRYPTO_ASSERT(SNI_OK == SNI_throwNativeIOException(LLCRYPTO_ERROR, "Can't register SNI native resource"));
			params->error_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS != params->error_code) {// cleanup
		params->result = params->error_code;
		if (NULL != public_key->ec_key) {
			wc_ecc_free(public_key->ec_key);
			llcrypto_free(public_key->ec_key);
		}
		if (NULL != public_key) {
			llcrypto_free(public_key);
		}
	}

	llcrypto_free_job(job);
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (result=%d) \n", __func__, params->result);
	return (jint)params->result;
}

// -----------------------------------------------------------------------------
// LLCRYPTO_KEY_FACTORY*_action functions
// -----------------------------------------------------------------------------

void LLCRYPTO_KEY_FACTORY_IMPL_get_ec_public_key_from_raw_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s\n", __func__);
	LLCRYPTO_KEY_FACTORY_ec_public_key_from_raw_params_t *params =
		(LLCRYPTO_KEY_FACTORY_ec_public_key_from_raw_params_t *)job->params;

	uint8_t *curve_name = params->curve_name;
	uint8_t *x = params->x;
	uint8_t *y = params->y;

	params->error_code = LLCRYPTO_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

	LLCRYPTO_pub_key *public_key = (LLCRYPTO_pub_key *)llcrypto_calloc(1, sizeof(LLCRYPTO_pub_key));
	if (NULL == public_key) {
		params->error_code = LLCRYPTO_ERROR_OOM;
		LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("Failed to allocate LLCRYPTO_pub_key\n");
	} else {
		public_key->algo_type = ALGO_ECDSA;
	}

	ecc_key *key = NULL;
	if (LLCRYPTO_SUCCESS == params->error_code) {
		key = (ecc_key *)llcrypto_calloc(1, sizeof(ecc_key));
		if (NULL == key) {
			params->error_code = LLCRYPTO_ERROR_OOM;
			LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("Failed to allocate ecc_key\n");
		} else {
			public_key->ec_key = key;
		}
	}

	if (LLCRYPTO_SUCCESS == params->error_code) {
		int wc_ret = wc_ecc_init_ex(key, pHint, INVALID_DEVID);
		if (MEMORY_E == wc_ret) {
			params->error_code = LLCRYPTO_ERROR_OOM;
		} else if (0 != wc_ret) {
			params->error_code = LLCRYPTO_ERROR;
			LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("wc_ecc_init() failed with error: %d\n", wc_ret);
		} else {
			// Successful call of  wc_ecc_init_ex, nothing to do.
		}
	}

	int curve_id;
	if (LLCRYPTO_SUCCESS == params->error_code) {
		int wc_ret = wc_ecc_get_curve_id_from_name((char const *)curve_name);
		if (wc_ret < 0) {
			params->error_code = LLCRYPTO_ERROR;
			LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("wc_ecc_get_curve_id_from_name() failed with error: %d\n", wc_ret);
		} else {
			curve_id = wc_ret;
		}
	}

	if (LLCRYPTO_SUCCESS == params->error_code) {
		// CAUTION: the x and y inputs are coming from the BigInteger class which may add a sign bit in an extra byte in
		// the byte array. This byte is added at the beginning of the byte array and is equal to zero since x and y are
		// always positive values.
		// WolfCrypt expects an unsigned value so it is necessary to skip this extra byte when added.
		//
		// More information about BigInteger:
		// https://repository.microej.com/javadoc/microej_5.x/apis/java/math/BigInteger.html#toByteArray--
		uint8_t *unsigned_x = (x[0] == 0x00u) ? (x + 1) : x;
		uint8_t *unsigned_y = (y[0] == 0x00u) ? (y + 1) : y;

		int wc_ret = wc_ecc_import_unsigned(key, unsigned_x, unsigned_y, NULL, curve_id);
		if ((MEMORY_E == wc_ret) || (MP_MEM == wc_ret)) {
			params->error_code = LLCRYPTO_ERROR_OOM;
		} else if (0 != wc_ret) {
			params->error_code = LLCRYPTO_ERROR;
			LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("wc_ecc_import_unsigned() failed with error: %d\n", wc_ret);
		} else {
			params->result = (int32_t)public_key;
		}
	}
}

// --------------------------------------------------------------------------------
// LLCRYPTO_KEY_FACTORY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_algorithm_description(uint8_t *algorithm_name) {
	int32_t return_code = LLCRYPTO_ERROR;
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);
	int32_t nb_algorithms = sizeof(available_key_algorithms) / sizeof(LLCRYPTO_KEY_FACTORY_algorithm);
	LLCRYPTO_KEY_FACTORY_algorithm *algorithm = &available_key_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			break;
		}
		algorithm++;
	}

	if (0 <= nb_algorithms) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		return_code = (int32_t)algorithm;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_public_key_data(int32_t algorithm_id, uint8_t *format_name, uint8_t *encoded_key,
                                                      int32_t encoded_key_length) {
	int32_t return_code = LLCRYPTO_SUCCESS;
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);
	LLCRYPTO_pub_key *public_key = NULL;

	if (0 != strcmp((char *)format_name, x509_format)) {
		llcrypto_throw(LLCRYPTO_ERROR, "Invalid format name");
		return_code = LLCRYPTO_ERROR;
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		public_key = (LLCRYPTO_pub_key *)llcrypto_calloc(1, sizeof(LLCRYPTO_pub_key));
		if (NULL == public_key) {
			return_code = LLCRYPTO_ERROR_OOM;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLCRYPTO_KEY_FACTORY_algorithm *algorithm = (LLCRYPTO_KEY_FACTORY_algorithm *)algorithm_id;
		public_key->key_type = LLCRYPTO_KEY_TYPE_PUBLIC;
		return_code = algorithm->get_public_key_data(public_key, encoded_key, encoded_key_length);
		if ((LLCRYPTO_ERROR == return_code) && (NULL != public_key)) {
			llcrypto_free(public_key);
		}
	}

	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, (int)return_code);
	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_private_key_data(int32_t algorithm_id, uint8_t *format_name, uint8_t *encoded_key,
                                                       int32_t encoded_key_length) {
	int32_t return_code = LLCRYPTO_SUCCESS;
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);
	LLCRYPTO_priv_key *private_key = NULL;

	if (0 != strcmp((char *)format_name, pkcs8_format)) {
		llcrypto_throw(LLCRYPTO_ERROR, "Invalid format name");
		return_code = LLCRYPTO_ERROR;
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		private_key = (LLCRYPTO_priv_key *)llcrypto_calloc(1, sizeof(LLCRYPTO_priv_key));
		if (NULL == private_key) {
			return_code = LLCRYPTO_ERROR_OOM;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLCRYPTO_KEY_FACTORY_algorithm *algorithm = (LLCRYPTO_KEY_FACTORY_algorithm *)algorithm_id;
		private_key->key_type = LLCRYPTO_KEY_TYPE_PRIVATE;
		return_code = algorithm->get_private_key_data(private_key, encoded_key, encoded_key_length);
		if ((LLCRYPTO_ERROR == return_code) && (NULL != private_key)) {
			llcrypto_free(private_key);
		}
	}

	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, (int)return_code);
	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_private_key_close_id(int32_t algorithm_id) {
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_KEY_FACTORY_algorithm *algorithm = (LLCRYPTO_KEY_FACTORY_algorithm *)algorithm_id;
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s(algorithm=\"%s\")\n", __func__, algorithm->name);
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)algorithm->private_key_close;
}

// See the header file for the function documentation
int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_public_key_close_id(int32_t algorithm_id) {
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_KEY_FACTORY_algorithm *algorithm = (LLCRYPTO_KEY_FACTORY_algorithm *)algorithm_id;
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s(algorithm=\"%s\")\n", __func__, algorithm->name);
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)algorithm->public_key_close;
}

// see LLCRYPTO_KEY_AGREEMENT_impl.h
int32_t LLCRYPTO_KEY_FACTORY_IMPL_get_ec_public_key_from_raw(uint8_t *curveName, uint8_t *x, uint8_t *y) {
	LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("%s(curveName=\"%s\", x[%d], y[%d])\n",
	                                 __func__, curveName, SNI_getArrayLength(x), SNI_getArrayLength(y));

	jint result = LLCRYPTO_SUCCESS;
	MICROEJ_ASYNC_WORKER_job_t *job =
		MICROEJ_ASYNC_WORKER_allocate_job(&llcrypto_worker,
		                                  (SNI_callback)LLCRYPTO_KEY_FACTORY_IMPL_get_ec_public_key_from_raw);
	if (job == NULL) {
		// No job available, either:
		// - wait for a job to be available and this function to be executed again,
		// - or an exception is pending
		result = LLCRYPTO_JOB_UNAVAILABLE;
	}

	LLCRYPTO_KEY_FACTORY_ec_public_key_from_raw_params_t *params = NULL;
	if (LLCRYPTO_SUCCESS == result) {
		params = (LLCRYPTO_KEY_FACTORY_ec_public_key_from_raw_params_t *)job->params;
		if ((strlen((char const *)curveName) > sizeof(params->curve_name)) ||
		    (SNI_getArrayLength(x) > sizeof(params->x)) ||
		    (SNI_getArrayLength(y) > sizeof(params->y))) {
			LLCRYPTO_KEY_FACTORY_DEBUG_TRACE("Invalid parameter(s) size");
			result = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		llcrypto_memcpy(params->curve_name, curveName, strlen((char const *)curveName));
		params->curve_name[strlen((char const *)curveName)] = '\0';

		llcrypto_memcpy(params->x, x, SNI_getArrayLength(x));
		llcrypto_memcpy(params->y, y, SNI_getArrayLength(y));

		int32_t status = llcrypto_async_exec(job,
		                                     LLCRYPTO_KEY_FACTORY_IMPL_get_ec_public_key_from_raw_action,
		                                     (SNI_callback)LLCRYPTO_KEY_FACTORY_IMPL_get_ec_public_key_from_raw_on_done);
		if (status == LLCRYPTO_SUCCESS) {
			// Wait for the action to be done
			result = SNI_IGNORED_RETURNED_VALUE; //returned value not used
		} else {
			// An error occurred and MICROEJ_ASYNC_WORKER_async_exec has thrown a SNI exception
			// and the job must be released explicitly.
			result = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_ERROR == result) {
		// Release the job when an error occured when the job has been allocated.
		llcrypto_free_job(job);
	} else if (LLCRYPTO_JOB_UNAVAILABLE == result) {
		// The Java thread is suspended until a job is available, or a NativeException is pending: the returned
		// value is ignored and must not be mistaken for a LLCRYPTO_CONSTANTS.h code.
		result = SNI_IGNORED_RETURNED_VALUE;
	} else {
		// Nothing to do: the result is returned as is.
	}

	return result;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
