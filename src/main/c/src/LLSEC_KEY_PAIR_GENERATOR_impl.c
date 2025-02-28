/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Key pair generators.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_wolfcrypt.h>

#include <LLSEC_ERRORS.h>
#include <LLSEC_KEY_PAIR_GENERATOR_impl.h>
#include <sni.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef void (*LLSEC_KEY_PAIR_GENERATOR_close)(void *native_id);

typedef struct {
	char *name;
	LLSEC_KEY_PAIR_GENERATOR_close close;
} LLSEC_KEY_PAIR_GENERATOR_algorithm;

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

//RSA
static int32_t LLSEC_KEY_PAIR_GENERATOR_RSA_wolfcrypt_generateKeyPair(int32_t rsa_Key_size,
                                                                      int32_t rsa_public_exponent);
static void LLSEC_KEY_PAIR_GENERATOR_RSA_wolfcrypt_close(void *native_id);

//EC
static int32_t LLSEC_KEY_PAIR_GENERATOR_EC_wolfcrypt_generateKeyPair(uint8_t *ec_curve_stdname);
static void LLSEC_KEY_PAIR_GENERATOR_EC_wolfcrypt_close(void *native_id);

// cppcheck-suppress [misra-c2012-8.9] : Define here for code readability even if it called once in this file.
static LLSEC_KEY_PAIR_GENERATOR_algorithm supportedAlgorithms[2] = {
	{
		.name = "RSA",
		.close = LLSEC_KEY_PAIR_GENERATOR_RSA_wolfcrypt_close
	},
	{
		.name = "EC",
		.close = LLSEC_KEY_PAIR_GENERATOR_EC_wolfcrypt_close
	}
};

/**
 * @brief   Generates a Wolfcrypt RSA key pair.
 *
 * @param[in]  rsa_Key_size  Size of the keys to generate.
 * @param[in]  rsa_public_exponent  Exponent parameter to use for generating the key.
 *
 * @return     the reference of the generated RSA key structure,  LLSEC_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t LLSEC_KEY_PAIR_GENERATOR_RSA_wolfcrypt_generateKeyPair(int32_t rsa_Key_size,
                                                                      int32_t rsa_public_exponent) {
	LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE("%s\n", __func__);
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	LLSEC_priv_key *key = NULL;
	void *native_id = NULL;

	if (RSA_MAX_SIZE < rsa_Key_size) {
		(void)SNI_throwNativeException(-1, "RSA key size requested exceeds maximum supported");
		return_code = LLSEC_ERROR;
	}

	RsaKey *ctx = LLSEC_calloc(1, sizeof(RsaKey)); //RSA key structure
	if ((LLSEC_SUCCESS == return_code) && (NULL == ctx)) {
		(void)SNI_throwNativeException(-1, "Could not allocate key buffer");
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		wolfcrypt_rc = wc_InitRsaKey(ctx, NULL);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "RSA key generation, initialization error");
			return_code = LLSEC_ERROR;
		}
	}
	if (LLSEC_SUCCESS == return_code) {
		wolfcrypt_rc = wc_MakeRsaKey(ctx, rsa_Key_size, rsa_public_exponent, llsec_wc_RNG);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "RSA key generation error");
			return_code = LLSEC_ERROR;
		} else {
			key = (LLSEC_priv_key *)LLSEC_calloc(1, sizeof(LLSEC_priv_key));
			if (NULL == key) {
				(void)SNI_throwNativeException(-2, "Could not allocate key buffer");
				return_code = LLSEC_ERROR;
			}
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		key->key = (char *)ctx;
		key->key_type = TYPE_RSA;

		// Register the key to be managed by SNI as a native resource.
		// the close callback when be called when the key is collected by the GC
		// The key is freed in the close callback
		native_id = (void *)key;
		if (SNI_OK != SNI_registerResource(native_id, LLSEC_KEY_PAIR_GENERATOR_RSA_wolfcrypt_close, NULL)) {
			(void)SNI_throwNativeException(-1, "Could not register native resource");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		return_code = (int)native_id;
	} else {
		if (NULL != ctx) {
			wc_FreeRsaKey(ctx);
			LLSEC_free(ctx);
		}
		if (NULL != key) {
			LLSEC_free(key);
		}
	}

	return return_code;
}

/**
 * @brief   Generates a Wolfcrypt ECC key pair.
 *
 * @param[in]  ec_curve_stdname Pointer to the string containing the name of the curve to use.
 *
 * @return     the reference of the generated ECC key structure,  LLSEC_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t LLSEC_KEY_PAIR_GENERATOR_EC_wolfcrypt_generateKeyPair(uint8_t *ec_curve_stdname) {
	LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE("%s\n", __func__);
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	WC_RNG *rng_ctx;
	LLSEC_priv_key *key = NULL;
	void *native_id = NULL;

	ecc_key *ctx = LLSEC_calloc(1, sizeof(ecc_key)); // EC key structure
	if (NULL == ctx) {
		(void)SNI_throwNativeException(-1, "Could not allocate key buffer");
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		wolfcrypt_rc = wc_ecc_init(ctx);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "Could not initialize ECC key");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		int curveId = llsec_ecc_get_wc_curve_id(ec_curve_stdname);
		wolfcrypt_rc = wc_ecc_make_key(llsec_wc_RNG, wc_ecc_get_curve_size_from_id(curveId), ctx);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "ECC key generation error");
			return_code = LLSEC_ERROR;
		} else {
			key = (LLSEC_priv_key *)LLSEC_calloc(1, sizeof(LLSEC_priv_key));
			if (NULL == key) {
				(void)SNI_throwNativeException(-2, "Could not allocate key buffer");
				return_code = LLSEC_ERROR;
			}
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		key->key = (char *)ctx;
		key->key_type = TYPE_ECDSA;

		// Register the key to be managed by SNI as a native resource.
		// the close callback when be called when the key is collected by the GC
		// The key is freed in the close callback
		native_id = (void *)key;
		if (SNI_OK != SNI_registerResource(native_id, LLSEC_KEY_PAIR_GENERATOR_EC_wolfcrypt_close, NULL)) {
			(void)SNI_throwNativeException(-1, "Could not register native resource");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		return_code = (int)native_id;
	} else {
		if (NULL != ctx) {
			wc_ecc_free(ctx);
			LLSEC_free(ctx);
		}
		if (NULL != key) {
			LLSEC_free(key);
		}
	}

	return return_code;
}

/**
 * @brief   Frees the resources and context associated of an Wolfcrypt RSA key structure.
 *
 * @param[in]  native_id  Pointer to the RSA key structure
 *
 */
static void LLSEC_KEY_PAIR_GENERATOR_RSA_wolfcrypt_close(void *native_id) {
	LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE("%s\n", __func__);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_priv_key *key = (LLSEC_priv_key *)native_id;
	wc_FreeRsaKey((RsaKey *)key->key);
	LLSEC_free(key->key);
	LLSEC_free(key);
}

/**
 * @brief   Frees the resources and context associated of an Wolfcrypt ECC key structure.
 *
 * @param[in]  native_id  Pointer to the ECC key structure
 *
 */
static void LLSEC_KEY_PAIR_GENERATOR_EC_wolfcrypt_close(void *native_id) {
	LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE("%s\n", __func__);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_priv_key *key = (LLSEC_priv_key *)native_id;
	wc_ecc_free((ecc_key *)key->key);
	LLSEC_free(key->key);
	LLSEC_free(key);
}

// --------------------------------------------------------------------------------
// LLSEC_KEY_PAIR_GENERATOR_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_KEY_PAIR_GENERATOR_IMPL_get_algorithm(uint8_t *algorithm_name) {
	int32_t return_code = LLSEC_ERROR;
	LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE("%s \n", __func__);

	int32_t nb_algorithms = sizeof(supportedAlgorithms) / sizeof(LLSEC_KEY_PAIR_GENERATOR_algorithm);
	LLSEC_KEY_PAIR_GENERATOR_algorithm *algorithm = &supportedAlgorithms[0];

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
int32_t LLSEC_KEY_PAIR_GENERATOR_IMPL_generateKeyPair(int32_t algorithm_id, int32_t rsa_key_size,
                                                      int32_t rsa_public_exponent, uint8_t *ec_curve_stdname) {
	LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE("%s \n", __func__);
	int32_t return_code = LLSEC_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_KEY_PAIR_GENERATOR_algorithm *algorithm = (LLSEC_KEY_PAIR_GENERATOR_algorithm *)algorithm_id;
	if (0 == strcmp(algorithm->name, "RSA")) {
		return_code = LLSEC_KEY_PAIR_GENERATOR_RSA_wolfcrypt_generateKeyPair(rsa_key_size, rsa_public_exponent);
	} else if (0 == strcmp(algorithm->name, "EC")) {
		return_code = LLSEC_KEY_PAIR_GENERATOR_EC_wolfcrypt_generateKeyPair(ec_curve_stdname);
	} else {
		// Algorithm not found error.
		// this should never happen because the algorithm_id is a valid algorithm at this level.
		(void)SNI_throwNativeException(LLSEC_ERROR, "Unsupported algorithm");
		return_code = LLSEC_ERROR;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_KEY_PAIR_GENERATOR_IMPL_get_close_id(int32_t algorithm_id) {
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_KEY_PAIR_GENERATOR_algorithm *algorithm = (LLSEC_KEY_PAIR_GENERATOR_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)algorithm->close;
}
