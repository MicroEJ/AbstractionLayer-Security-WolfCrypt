/*
 * C
 *
 * Copyright 2024 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief MicroEJ Security low level API
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_SECRET_KEY_FACTORY_impl.h>
#include <LLSEC_wolfcrypt.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef int32_t (*LLSEC_SECRET_KEY_FACTORY_get_key_data)(LLSEC_secret_key *secret_key, int wc_type, uint8_t *password,
                                                         int32_t password_length, uint8_t *salt, int32_t salt_length,
                                                         int32_t iterations, int32_t key_length);
typedef void (*LLSEC_SECRET_KEY_FACTORY_key_close)(void *native_id);

int32_t     LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data(LLSEC_secret_key *secret_key, int wc_type,
                                                                   uint8_t *password, int32_t password_length,
                                                                   uint8_t *salt, int32_t salt_length,
                                                                   int32_t iterations, int32_t key_length);

typedef struct {
	const char *name;
	int wc_type;
	LLSEC_SECRET_KEY_FACTORY_get_key_data get_key_data;
	LLSEC_SECRET_KEY_FACTORY_key_close key_close;
} LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm;

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static void LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_key_close(void *native_id);
void        LLSEC_SECRET_KEY_FACTORY_wolfcrypt_free_secret_key(LLSEC_secret_key *secret_key);

// cppcheck-suppress [misra-c2012-8.9] : Define here for code readability even if it called once in this file.
static LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm available_algorithms[] = {
#if WOLF_CONF_SHA1 == 1
	{
		.name = "PBKDF2WithHmacSHA1",
		.wc_type = WC_SHA,
		.get_key_data = LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data,
		.key_close = LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_key_close
	},
#endif
#if WOLF_CONF_SHA2_224 == 1
	{
		.name = "PBKDF2WithHmacSHA224",
		.wc_type = WC_SHA224,
		.get_key_data = LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data,
		.key_close = LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_key_close
	},
#endif
#if WOLF_CONF_SHA2_256 == 1
	{
		.name = "PBKDF2WithHmacSHA256",
		.wc_type = WC_SHA256,
		.get_key_data = LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data,
		.key_close = LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_key_close
	},
#endif
#if WOLF_CONF_SHA2_384 == 1
	{
		.name = "PBKDF2WithHmacSHA384",
		.wc_type = WC_SHA384,
		.get_key_data = LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data,
		.key_close = LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_key_close
	},
#endif
#if WOLF_CONF_SHA2_512 == 1
	{
		.name = "PBKDF2WithHmacSHA512",
		.wc_type = WC_SHA512,
		.get_key_data = LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data,
		.key_close = LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_key_close
	}
#endif
};

/**
 * @brief   Frees the resources associated of an secret key native structure.
 *
 * @param[in]  secret_key  Pointer to the secret key structure
 *
 */
void LLSEC_SECRET_KEY_FACTORY_wolfcrypt_free_secret_key(LLSEC_secret_key *secret_key) {
	if (NULL != secret_key->key) {
		LLSEC_free(secret_key->key);
	}
	if (NULL != secret_key) {
		LLSEC_free(secret_key);
	}
}

/**
 * @brief   Creates a key native structure  with the provided elements.
 *
 * @param[in]  secret_key       Pointer to the key native structure.
 * @param[in]  wc_type          Hashing algorithm to use. Valid choices are: WC_MD5, WC_SHA, WC_SHA224, WC_SHA256,
 * WC_SHA384, WC_SHA512, WC_SHA3_224, WC_SHA3_256, WC_SHA3_384, WC_SHA3_512, WC_SM3
 * @param[in]  password         Pointer to a buffer containing the password
 * @param[in]  password_length  Size of the password (in bytes).
 * @param[in]  salt             Pointer to a buffer containing a salt.
 * @param[in]  salt_length      Size of the salt (in bytes).
 * @param[in]  iterations       Number of times to process the hash.
 * @param[in]  key_length       Desired length of the derived key.
 *
 * @return     Reference to kthe key native structure created,  LLSEC_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
int32_t LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_get_key_data(LLSEC_secret_key *secret_key, int wc_type,
                                                               uint8_t *password, int32_t password_length,
                                                               uint8_t *salt, int32_t salt_length, int32_t iterations,
                                                               int32_t key_length) {
	LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);

	int32_t return_code = LLSEC_SUCCESS;

	/* Allocate resources */
	secret_key->key = LLSEC_calloc(key_length, sizeof(byte));
	if (NULL == secret_key->key) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "LLSEC_calloc() of the key failed");
		return_code = LLSEC_ERROR;
	}

	/* PKCS#5 PBKDF2 using HMAC */
	if (LLSEC_SUCCESS == return_code) {
		secret_key->key_length = key_length;
		int wolfcrypt_rc = wc_PBKDF2(secret_key->key,
		                             (const byte *)password,
		                             (size_t)password_length,
		                             (byte *)salt,
		                             (size_t)salt_length,
		                             (unsigned int)iterations,
		                             (uint32_t)secret_key->key_length,
		                             wc_type);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE("%s wolfcrypt_pkcs5_pbkdf2_hmac() failed (rc = %d)\n", __func__,
			                                     wolfcrypt_rc);
			(void)SNI_throwNativeException(wolfcrypt_rc, "wolfcrypt_pkcs5_pbkdf2_hmac() failed");
			return_code = LLSEC_ERROR;
		}
	}

	/* Register SNI close callback */
	if (LLSEC_SUCCESS == return_code) {
		if (SNI_OK != SNI_registerResource((void *)secret_key,
		                                   (SNI_closeFunction)LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_key_close,
		                                   NULL)) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't register SNI native resource");
			return_code = LLSEC_ERROR;
		}
	}

	/* Return key struct addr (native_id) */
	if (LLSEC_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		return_code = (int32_t)secret_key;
		LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE("%s wc_PBKDF2() success. (native_id = %d)\n", __func__, (int)return_code);
	} else {
		LLSEC_SECRET_KEY_FACTORY_wolfcrypt_free_secret_key(secret_key);
	}

	return return_code;
}

/**
 * @brief   Frees the resources associated of an secret key native structure.
 *
 * @param[in]  native_id  Pointer to the secret key native structure
 *
 * @note Throws NativeIOException on error.
 *
 */
static void LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_key_close(void *native_id) {
	LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE("%s (native_id = %p)\n", __func__, native_id);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_secret_key *secret_key = (LLSEC_secret_key *)native_id;

	/* Release resources */
	LLSEC_SECRET_KEY_FACTORY_wolfcrypt_free_secret_key(secret_key);

	/* Unregister SNI close callback */
	if (SNI_OK != SNI_unregisterResource((void *)native_id,
	                                     (SNI_closeFunction)LLSEC_SECRET_KEY_FACTORY_PBKDF2_wolfcrypt_key_close)) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "Can't unregister SNI native resource");
	}
}

// --------------------------------------------------------------------------------
// LLSEC_SECRET_KEY_FACTORY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_SECRET_KEY_FACTORY_IMPL_get_algorithm(uint8_t *algorithm_name) {
	LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE("%s \n", __func__);
	int32_t return_code = LLSEC_ERROR;
	int32_t nb_algorithms = sizeof(available_algorithms) / sizeof(LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm);
	LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm *algorithm = &available_algorithms[0];

	/* Check corresponding algorithm */
	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE("%s Algorithm %s found\n", __func__, algorithm->name);
			break;
		}
		algorithm++;
	}

	if (0 <= nb_algorithms) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		return_code = (int32_t)algorithm;
	}
	LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE("%s Return handler = %d\n", __func__, (int)return_code);

	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_SECRET_KEY_FACTORY_IMPL_get_key_data(int32_t algorithm_id, uint8_t *password, int32_t password_length,
                                                   uint8_t *salt, int32_t salt_length, int32_t iterations,
                                                   int32_t key_length) {
	LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE("%s password length = %d, salt length = %d, key length = %d (handler = %d)\n",
	                                     __func__, (int)password_length, (int)salt_length, (int)key_length,
	                                     (int)algorithm_id);
	int32_t return_code = LLSEC_ERROR;

	/* Allocate secret key structure */
	LLSEC_secret_key *secret_key = (LLSEC_secret_key *)LLSEC_calloc(1, sizeof(LLSEC_secret_key));
	if (NULL == secret_key) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "Can't allocate LLSEC_secret_key structure");
	} else {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm *algorithm = (LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm *)algorithm_id;
		return_code = algorithm->get_key_data(secret_key, algorithm->wc_type, password, password_length, salt,
		                                      salt_length, iterations, key_length / 8);
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_SECRET_KEY_FACTORY_IMPL_get_close_id(int32_t algorithm_id) {
	LLSEC_SECRET_KEY_FACTORY_DEBUG_TRACE("%s (handler = %d)\n", __func__, (int)algorithm_id);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm *algorithm = (LLSEC_SECRET_KEY_FACTORY_IMPL_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)algorithm->key_close;
}
