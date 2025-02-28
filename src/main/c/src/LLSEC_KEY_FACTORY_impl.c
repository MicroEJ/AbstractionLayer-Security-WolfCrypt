/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Private & Public Key PKCS8 decoding.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_ERRORS.h>
#include <LLSEC_KEY_FACTORY_impl.h>
#include <LLSEC_wolfcrypt.h>
#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef int32_t (*LLSEC_KEY_FACTORY_get_private_key_data)(LLSEC_priv_key *priv_key, uint8_t *encoded_key,
                                                          int32_t encoded_key_length);
typedef int32_t (*LLSEC_KEY_FACTORY_get_public_key_data)(LLSEC_pub_key *pub_key, uint8_t *encoded_key,
                                                         int32_t encoded_key_length);
typedef void (*LLSEC_KEY_FACTORY_key_close)(void *native_id);

typedef struct {
	char *name;
	LLSEC_KEY_FACTORY_get_private_key_data get_private_key_data;
	LLSEC_KEY_FACTORY_get_public_key_data get_public_key_data;
	LLSEC_KEY_FACTORY_key_close private_key_close;
	LLSEC_KEY_FACTORY_key_close public_key_close;
} LLSEC_KEY_FACTORY_algorithm;

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

static int32_t LLSEC_KEY_FACTORY_RSA_wolfcrypt_get_private_key_data(LLSEC_priv_key *priv_key, uint8_t *encoded_key,
                                                                    int32_t encoded_key_length);
static int32_t LLSEC_KEY_FACTORY_RSA_wolfcrypt_get_public_key_data(LLSEC_pub_key *pub_key, uint8_t *encoded_key,
                                                                   int32_t encoded_key_length);
static int32_t LLSEC_KEY_FACTORY_EC_wolfcrypt_get_private_key_data(LLSEC_priv_key *priv_key, uint8_t *encoded_key,
                                                                   int32_t encoded_key_length);
static int32_t LLSEC_KEY_FACTORY_EC_wolfcrypt_get_public_key_data(LLSEC_pub_key *pub_key, uint8_t *encoded_key,
                                                                  int32_t encoded_key_length);
static void LLSEC_KEY_FACTORY_wolfcrypt_private_key_close(void *native_id);
static void LLSEC_KEY_FACTORY_wolfcrypt_public_key_close(void *native_id);

// cppcheck-suppress [misra-c2012-8.9] : Define here for code readability even if it called once in this file.
static LLSEC_KEY_FACTORY_algorithm available_key_algorithms[2] = {
	{
		.name = "RSA",
		.get_private_key_data = LLSEC_KEY_FACTORY_RSA_wolfcrypt_get_private_key_data,
		.get_public_key_data = LLSEC_KEY_FACTORY_RSA_wolfcrypt_get_public_key_data,
		.private_key_close = LLSEC_KEY_FACTORY_wolfcrypt_private_key_close,
		.public_key_close = LLSEC_KEY_FACTORY_wolfcrypt_public_key_close
	},
	{
		.name = "EC",
		.get_private_key_data = LLSEC_KEY_FACTORY_EC_wolfcrypt_get_private_key_data,
		.get_public_key_data = LLSEC_KEY_FACTORY_EC_wolfcrypt_get_public_key_data,
		.private_key_close = LLSEC_KEY_FACTORY_wolfcrypt_private_key_close,
		.public_key_close = LLSEC_KEY_FACTORY_wolfcrypt_public_key_close
	}
};

/**
 * @brief   Creates a Wolfcrypt RSA private key structure from a provided DER format the private key.
 *
 * @param[in]  priv_key  Pointer to the private key structure
 * @param[in]  encoded_key  Pointer to the buffer containing the DER encoded private key.
 * @param[in]  encoded_key_length  Size of the DER encoded private key.
 *
 * @return     LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t LLSEC_KEY_FACTORY_RSA_wolfcrypt_get_private_key_data(LLSEC_priv_key *priv_key, uint8_t *encoded_key,
                                                                    int32_t encoded_key_length) {
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s (key = %p) \n", __func__, priv_key);
	LLSEC_KEY_FACTORY_DEBUG_TRACE("encLen %d, strlen: %zu, enc:%s  \n", (int)encoded_key_length,
	                              strlen((char *)encoded_key), encoded_key);

	int return_code = LLSEC_SUCCESS;
	int module_rc = LLSEC_WOLFCRYPT_SUCCESS;
	char *pers = NULL;

	word32 idx = 0;

	priv_key->key_type = TYPE_RSA;

	RsaKey *wolfcrypt_rsa_ctx;
	WC_RNG *wolfcrypt_rng_ctx;

	// RSA structure allocation
	wolfcrypt_rsa_ctx = LLSEC_calloc(1, sizeof(RsaKey)); //RSA key structure
	if (NULL == wolfcrypt_rsa_ctx) {
		return_code = LLSEC_ERROR;
	} else {
		module_rc = wc_InitRsaKey(wolfcrypt_rsa_ctx, NULL);
		if (LLSEC_WOLFCRYPT_SUCCESS != module_rc) {
			wc_FreeRsaKey(wolfcrypt_rsa_ctx);
			LLSEC_free(wolfcrypt_rsa_ctx);
			(void)SNI_throwNativeException(module_rc, "RSA wolfcrypt init failed");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		pers = llsec_gen_random_str_internal(8);
		wolfcrypt_rng_ctx = wc_rng_new((byte *)pers, (word32)strlen(pers), NULL);
		if (NULL == wolfcrypt_rng_ctx) {
			(void)SNI_throwNativeException(module_rc, "Failed to initialize random number generator for RSA");
			wc_rng_free(wolfcrypt_rng_ctx);

			LLSEC_free((void *)pers);
			return_code = LLSEC_ERROR;
		} else {
			module_rc = wc_RsaSetRNG(wolfcrypt_rsa_ctx, wolfcrypt_rng_ctx);
			if (LLSEC_WOLFCRYPT_SUCCESS != module_rc) {
				wc_FreeRsaKey(wolfcrypt_rsa_ctx);
				wc_rng_free(wolfcrypt_rng_ctx);
				LLSEC_free(wolfcrypt_rsa_ctx);
				(void)SNI_throwNativeException(module_rc, "Failed to set random number generator for RSA Key Factory");
				return_code = LLSEC_ERROR;
			}
		}
	}
	if (LLSEC_SUCCESS == return_code) {
		module_rc = wc_RsaPrivateKeyDecode(encoded_key, &idx, wolfcrypt_rsa_ctx, encoded_key_length);
		if (LLSEC_WOLFCRYPT_SUCCESS != module_rc) {
			LLSEC_KEY_FACTORY_DEBUG_TRACE("wc_RsaPrivateKeyDecode failed (rc = %d)", module_rc);
			return_code = LLSEC_ERROR;
		} else {
			priv_key->key = (char *)wolfcrypt_rsa_ctx;
			if (NULL == priv_key->key) {
				(void)SNI_throwNativeException(LLSEC_ERROR, "RSA context extraction failed");
				return_code = LLSEC_ERROR;
			}
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		void *native_id = (void *)priv_key;
		if (SNI_OK != SNI_registerResource(native_id, (SNI_closeFunction)LLSEC_KEY_FACTORY_wolfcrypt_private_key_close,
		                                   NULL)) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't register SNI native resource");
			wc_FreeRsaKey((RsaKey *)priv_key->key);
			LLSEC_free(wolfcrypt_rsa_ctx);
			return_code = LLSEC_ERROR;
		} else {
			// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
			return_code = (int32_t)native_id;
		}
	}

	if (NULL != pers) {
		LLSEC_free((void *)pers);
	}
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, return_code);
	return return_code;
}

/**
 * @brief   Creates a Wolfcrypt RSA public key structure from a provided DER format the public key.
 *
 * @param[in]  pub_key  Pointer to the public key structure
 * @param[in]  encoded_key  Pointer to the buffer containing the DER encoded public key.
 * @param[in]  encoded_key_length  Size of the DER encoded public key.
 *
 * @return     LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t LLSEC_KEY_FACTORY_RSA_wolfcrypt_get_public_key_data(LLSEC_pub_key *pub_key, uint8_t *encoded_key,
                                                                   int32_t encoded_key_length) {
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s (key = %p) \n", __func__, pub_key);

	int return_code = LLSEC_SUCCESS;
	int module_rc = LLSEC_WOLFCRYPT_SUCCESS;

	word32 idx = 0;

	pub_key->key_type = TYPE_RSA;

	RsaKey *wolfcrypt_rsa_ctx;

	// RSA structure allocation
	wolfcrypt_rsa_ctx = LLSEC_calloc(1, sizeof(RsaKey)); //RSA key structure
	if (NULL == wolfcrypt_rsa_ctx) {
		(void)SNI_throwNativeException(-1, "Could not allocate key buffer");
		return_code = LLSEC_ERROR;
	} else {
		module_rc = wc_InitRsaKey(wolfcrypt_rsa_ctx, NULL);
		if (LLSEC_WOLFCRYPT_SUCCESS != module_rc) {
			wc_FreeRsaKey(wolfcrypt_rsa_ctx);
			LLSEC_free(wolfcrypt_rsa_ctx);
			(void)SNI_throwNativeException(module_rc, "RSA wolfcrypt init failed");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		module_rc = wc_RsaPublicKeyDecode(encoded_key, &idx, wolfcrypt_rsa_ctx, encoded_key_length);
		if (LLSEC_WOLFCRYPT_SUCCESS != module_rc) {
			LLSEC_KEY_FACTORY_DEBUG_TRACE("wc_RsaPublicKeyDecode failed (rc = %d)", module_rc);
			wc_FreeRsaKey(wolfcrypt_rsa_ctx);
			LLSEC_free(wolfcrypt_rsa_ctx);
			return_code = LLSEC_ERROR;
		} else {
			pub_key->key = (char *)wolfcrypt_rsa_ctx;
			if (NULL == pub_key->key) {
				(void)SNI_throwNativeException(LLSEC_ERROR, "RSA context extraction failed");
				return_code = LLSEC_ERROR;
			}
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		void *native_id = (void *)pub_key;
		if (SNI_OK != SNI_registerResource(native_id, (SNI_closeFunction)LLSEC_KEY_FACTORY_wolfcrypt_public_key_close,
		                                   NULL)) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't register SNI native resource");
			wc_FreeRsaKey((RsaKey *)pub_key->key);
			LLSEC_free(pub_key->key);
			return_code = LLSEC_ERROR;
		} else {
			// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
			return_code = (int32_t)native_id;
		}
	}

	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, return_code);
	return return_code;
}

/**
 * @brief Frees the resources and context associated of an Wolfcrypt private key structure.
 *
 * @param[in]  native_id  Pointer to  the Wolfcrypt private key structure.
 *
 */
static void LLSEC_KEY_FACTORY_wolfcrypt_private_key_close(void *native_id) {
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_priv_key *key = (LLSEC_priv_key *)native_id;
	if (TYPE_RSA == key->key_type) {
		wc_FreeRsaKey((RsaKey *)key->key);
	}
	if (TYPE_ECDSA == key->key_type) {
		wc_ecc_free((ecc_key *)key->key);
	}

	if (NULL != key) {
		LLSEC_free(key);
	}
}

/**
 * @brief Frees the resources and context associated of an Wolfcrypt public key structure.
 *
 * @param[in]  native_id  Pointer to  the Wolfcrypt public key structure.
 *
 */
static void LLSEC_KEY_FACTORY_wolfcrypt_public_key_close(void *native_id) {
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_pub_key *key = (LLSEC_pub_key *)native_id;
	if (TYPE_RSA == key->key_type) {
		wc_FreeRsaKey((RsaKey *)key->key);
	}
	if (TYPE_ECDSA == key->key_type) {
		wc_ecc_free((ecc_key *)key->key);
	}

	if (NULL != key) {
		LLSEC_free(key);
	}
}

/**
 * @brief   Creates a Wolfcrypt ECC private key structure from a provided DER format the private key.
 *
 * @param[in]  priv_key  Pointer to the private key structure
 * @param[in]  encoded_key  Pointer to the buffer containing the DER encoded private key.
 * @param[in]  encoded_key_length  Size of the DER encoded private key.
 *
 * @return     LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t LLSEC_KEY_FACTORY_EC_wolfcrypt_get_private_key_data(LLSEC_priv_key *priv_key, uint8_t *encoded_key,
                                                                   int32_t encoded_key_length) {
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s (key = %p) \n", __func__, priv_key);
	LLSEC_KEY_FACTORY_DEBUG_TRACE("encLen %d, strlen: %zu, enc:%s  \n", (int)encoded_key_length,
	                              strlen((char *)encoded_key), encoded_key);
	int return_code = LLSEC_SUCCESS;
	int module_rc = LLSEC_WOLFCRYPT_SUCCESS;
	char *pers = NULL;

	word32 idx = 0;

	priv_key->key_type = TYPE_ECDSA;

	ecc_key *wolfcrypt_ec_ctx;

	// EC structure allocation
	wolfcrypt_ec_ctx = LLSEC_calloc(1, sizeof(ecc_key)); //EC key structure
	if (NULL == wolfcrypt_ec_ctx) {
		(void)SNI_throwNativeException(-1, "Cannot allocate key buffer");
		return_code = LLSEC_ERROR;
	} else {
		module_rc = wc_ecc_init(wolfcrypt_ec_ctx);
		if (LLSEC_WOLFCRYPT_SUCCESS != module_rc) {
			wc_ecc_free(wolfcrypt_ec_ctx);
			LLSEC_free(wolfcrypt_ec_ctx);
			(void)SNI_throwNativeException(module_rc, "EC wolfcrypt init failed");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		module_rc = wc_EccPrivateKeyDecode(encoded_key, &idx, wolfcrypt_ec_ctx, encoded_key_length);
		if (LLSEC_WOLFCRYPT_SUCCESS != module_rc) {
			LLSEC_KEY_FACTORY_DEBUG_TRACE("wc_EccPrivateKeyDecode failed (rc = %d)", module_rc);
			return_code = LLSEC_ERROR;
		} else {
			priv_key->key = (char *)wolfcrypt_ec_ctx;
			if (NULL == priv_key->key) {
				(void)SNI_throwNativeException(LLSEC_ERROR, "EC context extraction failed");
				return_code = LLSEC_ERROR;
			}
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		void *native_id = (void *)priv_key;
		if (SNI_OK != SNI_registerResource(native_id, (SNI_closeFunction)LLSEC_KEY_FACTORY_wolfcrypt_private_key_close,
		                                   NULL)) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't register SNI native resource");
			wc_ecc_free((ecc_key *)priv_key->key);
			LLSEC_free(wolfcrypt_ec_ctx);
			return_code = LLSEC_ERROR;
		} else {
			// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
			return_code = (int32_t)native_id;
		}
	}

	if (NULL != pers) {
		LLSEC_free((void *)pers);
	}
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, return_code);
	return return_code;
}

/**
 * @brief   Creates a Wolfcrypt ECC public key structure from a provided DER format the public key.
 *
 * @param[in]  pub_key  Pointer to the public key structure
 * @param[in]  encoded_key  Pointer to the buffer containing the DER encoded public key.
 * @param[in]  encoded_key_length  Size of the DER encoded public key.
 *
 * @return     LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t LLSEC_KEY_FACTORY_EC_wolfcrypt_get_public_key_data(LLSEC_pub_key *pub_key, uint8_t *encoded_key,
                                                                  int32_t encoded_key_length) {
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s (key = %p) \n", __func__, pub_key);

	int return_code = LLSEC_SUCCESS;
	int module_rc = LLSEC_WOLFCRYPT_SUCCESS;

	word32 idx = 0;

	pub_key->key_type = TYPE_ECDSA;

	ecc_key *wolfcrypt_ec_ctx;

	// EC structure allocation
	wolfcrypt_ec_ctx = LLSEC_calloc(1, sizeof(ecc_key)); //EC key structure
	if (NULL == wolfcrypt_ec_ctx) {
		return_code = LLSEC_ERROR;
	} else {
		module_rc = wc_ecc_init(wolfcrypt_ec_ctx);
		if (LLSEC_WOLFCRYPT_SUCCESS != module_rc) {
			wc_ecc_free(wolfcrypt_ec_ctx);
			LLSEC_free(wolfcrypt_ec_ctx);
			(void)SNI_throwNativeException(module_rc, "EC wolfcrypt init failed");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		module_rc = wc_EccPublicKeyDecode(encoded_key, &idx, wolfcrypt_ec_ctx, encoded_key_length);
		if (LLSEC_WOLFCRYPT_SUCCESS != module_rc) {
			LLSEC_KEY_FACTORY_DEBUG_TRACE("wc_EccPublicKeyDecode failed (rc = %d)", module_rc);
			wc_ecc_free(wolfcrypt_ec_ctx);
			LLSEC_free(wolfcrypt_ec_ctx);
			return_code = LLSEC_ERROR;
		} else {
			pub_key->key = (char *)wolfcrypt_ec_ctx;
			if (NULL == pub_key->key) {
				(void)SNI_throwNativeException(LLSEC_ERROR, "EC context extraction failed");
				return_code = LLSEC_ERROR;
			}
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		void *native_id = (void *)pub_key;
		if (SNI_OK != SNI_registerResource(native_id, (SNI_closeFunction)LLSEC_KEY_FACTORY_wolfcrypt_public_key_close,
		                                   NULL)) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't register SNI native resource");
			wc_ecc_free((ecc_key *)pub_key->key);
			LLSEC_free(pub_key->key);
			return_code = LLSEC_ERROR;
		} else {
			// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
			return_code = (int32_t)native_id;
		}
	}

	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, return_code);
	return return_code;
}

// --------------------------------------------------------------------------------
// LLSEC_KEY_FACTORY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_KEY_FACTORY_IMPL_get_algorithm_description(uint8_t *algorithm_name) {
	int32_t return_code = LLSEC_ERROR;
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);
	int32_t nb_algorithms = sizeof(available_key_algorithms) / sizeof(LLSEC_KEY_FACTORY_algorithm);
	LLSEC_KEY_FACTORY_algorithm *algorithm = &available_key_algorithms[0];

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
int32_t LLSEC_KEY_FACTORY_IMPL_get_public_key_data(int32_t algorithm_id, uint8_t *format_name, uint8_t *encoded_key,
                                                   int32_t encoded_key_length) {
	int32_t return_code = LLSEC_SUCCESS;
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);
	LLSEC_pub_key *public_key = NULL;

	if (0 != strcmp((char *)format_name, x509_format)) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "Invalid format name");
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		public_key = (LLSEC_pub_key *)LLSEC_calloc(1, sizeof(LLSEC_pub_key));
		if (NULL == public_key) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't allocate LLSEC_pub_key structure");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLSEC_KEY_FACTORY_algorithm *algorithm = (LLSEC_KEY_FACTORY_algorithm *)algorithm_id;
		return_code = algorithm->get_public_key_data(public_key, encoded_key, encoded_key_length);
		if ((LLSEC_ERROR == return_code) && (NULL != public_key)) {
			LLSEC_free(public_key);
		}
	}

	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, (int)return_code);
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_KEY_FACTORY_IMPL_get_private_key_data(int32_t algorithm_id, uint8_t *format_name, uint8_t *encoded_key,
                                                    int32_t encoded_key_length) {
	int32_t return_code = LLSEC_SUCCESS;
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);
	LLSEC_priv_key *private_key = NULL;

	if (0 != strcmp((char *)format_name, pkcs8_format)) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "Invalid format name");
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		private_key = (LLSEC_priv_key *)LLSEC_calloc(1, sizeof(LLSEC_priv_key));
		if (NULL == private_key) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't allocate LLSEC_priv_key structure");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLSEC_KEY_FACTORY_algorithm *algorithm = (LLSEC_KEY_FACTORY_algorithm *)algorithm_id;
		return_code = algorithm->get_private_key_data(private_key, encoded_key, encoded_key_length);
		if ((LLSEC_ERROR == return_code) && (NULL != private_key)) {
			LLSEC_free(private_key);
		}
	}

	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s (rc = %d)\n", __func__, (int)return_code);
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_KEY_FACTORY_IMPL_get_private_key_close_id(int32_t algorithm_id) {
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_KEY_FACTORY_algorithm *algorithm = (LLSEC_KEY_FACTORY_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)algorithm->private_key_close;
}

// See the header file for the function documentation
int32_t LLSEC_KEY_FACTORY_IMPL_get_public_key_close_id(int32_t algorithm_id) {
	LLSEC_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_KEY_FACTORY_algorithm *algorithm = (LLSEC_KEY_FACTORY_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)algorithm->public_key_close;
}
