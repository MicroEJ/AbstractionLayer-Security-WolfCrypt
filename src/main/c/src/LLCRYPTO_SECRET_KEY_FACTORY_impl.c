/*
 * C
 *
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief MicroEJ Crypto low level API
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_SECRET_KEY_FACTORY_impl.h>
#include <LLCRYPTO_SECRET_KEY_impl.h>
#include <LLCRYPTO_wolfcrypt.h>
#include <LLCRYPTO_common.h>

#include <string.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef int32_t (*LLCRYPTO_SECRET_KEY_FACTORY_get_key_data)(LLCRYPTO_secret_key *secret_key, int wc_type,
                                                            uint8_t *password,
                                                            int32_t password_length, uint8_t *salt, int32_t salt_length,
                                                            int32_t iterations, int32_t key_length);

int32_t     LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data(LLCRYPTO_secret_key *secret_key, int wc_type,
                                                                      uint8_t *password, int32_t password_length,
                                                                      uint8_t *salt, int32_t salt_length,
                                                                      int32_t iterations, int32_t key_length);

typedef struct {
	const char *name;
	int wc_type;
	LLCRYPTO_SECRET_KEY_FACTORY_get_key_data get_key_data;
} LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm;

// cppcheck-suppress [misra-c2012-8.9] : Define here for code readability even if it called once in this file.
static LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm available_algorithms[] = {
#ifndef NO_SHA
	{
		.name = "PBKDF2WithHmacSHA1",
		.wc_type = WC_SHA,
		.get_key_data = LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data
	},
#endif // NO_SHA
#ifdef WOLFSSL_SHA224
	{
		.name = "PBKDF2WithHmacSHA224",
		.wc_type = WC_SHA224,
		.get_key_data = LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data
	},
#endif // WOLFSSL_SHA224
#ifndef NO_SHA256
	{
		.name = "PBKDF2WithHmacSHA256",
		.wc_type = WC_SHA256,
		.get_key_data = LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data
	},
#endif // NO_SHA256
#ifdef WOLFSSL_SHA384
	{
		.name = "PBKDF2WithHmacSHA384",
		.wc_type = WC_SHA384,
		.get_key_data = LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data
	},
#endif // WOLFSSL_SHA384
#ifdef WOLFSSL_SHA512
	{
		.name = "PBKDF2WithHmacSHA512",
		.wc_type = WC_SHA512,
		.get_key_data = LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data
	}
#endif // WOLFSSL_SHA512
};

/**
 * @brief   Fills a secret key native structure using PBKDF2.
 *
 * @param[in]  secret_key       Pointer to the key native structure to fill. Owned by the caller.
 * @param[in]  wc_type          Hashing algorithm to use. Valid choices are: WC_MD5, WC_SHA, WC_SHA224, WC_SHA256,
 * WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256, WC_SHA3_384, WC_SHA3_512, WC_SM3
 * @param[in]  password         Pointer to a buffer containing the password
 * @param[in]  password_length  Size of the password (in bytes).
 * @param[in]  salt             Pointer to a buffer containing a salt.
 * @param[in]  salt_length      Size of the salt (in bytes).
 * @param[in]  iterations       Number of times to process the hash.
 * @param[in]  key_length       Desired length of the derived key (in bytes).
 *
 * @return     LLCRYPTO_SUCCESS on success, LLCRYPTO_ERROR otherwise.
 *
 * @note On failure, only secret_key->key is freed; secret_key itself is owned by the caller.
 *
 */
int32_t LLCRYPTO_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data(LLCRYPTO_secret_key *secret_key, int wc_type,
                                                                  uint8_t *password, int32_t password_length,
                                                                  uint8_t *salt, int32_t salt_length,
                                                                  int32_t iterations,
                                                                  int32_t key_length) {
	LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);

	int32_t return_code = LLCRYPTO_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

	/* Allocate key bytes */
	secret_key->key = (uint8_t *)llcrypto_calloc(key_length, sizeof(uint8_t));
	if (NULL == secret_key->key) {
		return_code = LLCRYPTO_ERROR_OOM;
	}

	/* PKCS#5 PBKDF2 using HMAC */
	if (LLCRYPTO_SUCCESS == return_code) {
		secret_key->key_length = key_length;
		int wolfcrypt_rc = wc_PBKDF2_ex(secret_key->key,
		                                (const byte *)password,
		                                (size_t)password_length,
		                                (byte *)salt,
		                                (size_t)salt_length,
		                                (unsigned int)iterations,
		                                (uint32_t)secret_key->key_length,
		                                wc_type, pHint, INVALID_DEVID);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE("%s wolfcrypt_pkcs5_pbkdf2_hmac() failed (rc = %d)\n", __func__,
			                                        wolfcrypt_rc);
			llcrypto_throw(wolfcrypt_rc, "wolfcrypt_pkcs5_pbkdf2_hmac() failed");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS != return_code) {
		/* Only free the key bytes; secret_key struct is owned by the caller */
		if (NULL != secret_key->key) {
			llcrypto_free(secret_key->key);
			secret_key->key = NULL;
		}
	} else {
		LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE("%s wc_PBKDF2() success.\n", __func__);
	}

	return return_code;
}

// --------------------------------------------------------------------------------
// LLCRYPTO_SECRET_KEY_FACTORY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLCRYPTO_SECRET_KEY_FACTORY_IMPL_get_algorithm(uint8_t *algorithm_name) {
	LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);
	int32_t return_code = LLCRYPTO_ERROR;
	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm);
	LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm *algorithm = &available_algorithms[0];
	/* Check corresponding algorithm */
	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE("%s Algorithm %s found\n", __func__, algorithm->name);
			break;
		}
		algorithm++;
	}

	if (0 <= nb_algorithms) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		return_code = (int32_t)algorithm;
	}
	LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE("%s Return handler = %d\n", __func__, (int)return_code);

	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_SECRET_KEY_FACTORY_IMPL_get_key_data(int32_t algorithm_id, uint8_t *password, int32_t password_length,
                                                      uint8_t *salt, int32_t salt_length, int32_t iterations,
                                                      int32_t key_length) {
	LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE(
		"%s password length = %d, salt length = %d, key length = %d (handler = %d)\n",
		__func__, (int)password_length, (int)salt_length, (int)key_length,
		(int)algorithm_id);
	int32_t return_code = LLCRYPTO_ERROR;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm *algorithm = (LLCRYPTO_SECRET_KEY_FACTORY_IMPL_algorithm *)algorithm_id;
	if (NULL != algorithm->get_key_data) {
		/* Allocate the LLCRYPTO_key wrapper so the native_id layout matches LLCRYPTO_SECRET_KEY_IMPL expectations */
		LLCRYPTO_key *key = (LLCRYPTO_key *)llcrypto_calloc(1, sizeof(LLCRYPTO_key));
		if (NULL == key) {
			return_code = LLCRYPTO_ERROR_OOM;
		} else {
			LLCRYPTO_secret_key *secret_key = (LLCRYPTO_secret_key *)llcrypto_calloc(1, sizeof(LLCRYPTO_secret_key));
			if (NULL == secret_key) {
				llcrypto_free(key);
				return_code = LLCRYPTO_ERROR_OOM;
			} else {
				key->algo_type = ALGO_NONE;
				key->key_type = LLCRYPTO_KEY_TYPE_SECRET;
				key->secret_key = secret_key;

				int32_t derive_rc = algorithm->get_key_data(secret_key, algorithm->wc_type, password,
				                                            password_length, salt, salt_length,
				                                            iterations, key_length / 8);
				if (LLCRYPTO_SUCCESS == derive_rc) {
					// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
					SNI_closeFunction close_fn =
						(SNI_closeFunction)(uintptr_t)LLCRYPTO_SECRET_KEY_IMPL_nativeGetCloseId();
					if (SNI_OK != SNI_registerResource((void *)key, close_fn, NULL)) {
						llcrypto_throw(LLCRYPTO_ERROR, "Can't register SNI native resource");
						if (NULL != secret_key->key) {
							llcrypto_free(secret_key->key);
						}
						llcrypto_free(secret_key);
						llcrypto_free(key);
					} else {
						// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
						return_code = (int32_t)key;
						LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE("%s success. (native_id = %d)\n", __func__,
						                                        (int)return_code);
					}
				} else {
					/* derive_rc already freed secret_key->key on failure */
					llcrypto_free(secret_key);
					llcrypto_free(key);
					if (LLCRYPTO_ERROR_OOM == derive_rc) {
						return_code = LLCRYPTO_ERROR_OOM;
					}
				}
			}
		}
	} else {
		llcrypto_throw(LLCRYPTO_ERROR, "Unsupported algorithm for secret key generation");
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_SECRET_KEY_FACTORY_IMPL_get_close_id(int32_t algorithm_id) {
	LLCRYPTO_SECRET_KEY_FACTORY_DEBUG_TRACE("%s (handler = %d)\n", __func__, (int)algorithm_id);

	/* Every key derived by this factory is wrapped in an LLCRYPTO_key and registered with the close function
	 * returned by LLCRYPTO_SECRET_KEY_IMPL_nativeGetCloseId(). The Java side hands the (resource, close id) pair to
	 * ej.sni.NativeResource, which rejects a pair that does not match the registration: the same id is returned. */
	(void)algorithm_id;
	return LLCRYPTO_SECRET_KEY_IMPL_nativeGetCloseId();
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
