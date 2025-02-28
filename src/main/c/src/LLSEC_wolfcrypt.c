/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Common functions implementation.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include "microej_time.h"
#include <LLSEC_configuration.h>
#include <LLSEC_wolfcrypt.h>

#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <stdint.h>

#if !defined(NO_ASN) && !defined(NO_ASN_TIME)
#include <microej.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#endif

// --------------------------------------------------------------------------------
// Variable declarations
// --------------------------------------------------------------------------------

WC_RNG *llsec_wc_RNG;

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

#if !defined(NO_ASN) && !defined(NO_ASN_TIME)

/**
 * @brief Function used by Wolfcrypt to determine the epoch time for the certificate validation.
 *
 * @return  Number of seconds that have elapsed since January 1, 1970.
 */
static time_t time_cb(time_t *t) {
	time_t current_time = microej_time_get_current_time(MICROEJ_FALSE);
	if (NULL != t) {
		*t = current_time;
	}
	return current_time;
}

/**
 * @brief Function called to set the function used by Wolfcrypt to determine the epoch time for certificate validation.
 *
 */
static void llsec_init_time_function(void) {
	(void)wc_SetTimeCb(time_cb);
}

#endif

// --------------------------------------------------------------------------------
// Public functions
// --------------------------------------------------------------------------------

/**
 * @brief Initializes elements needed by the Crypto module to work with Wolfcrypt.
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 */
int llsec_wc_initialize(void) {
	int return_code = LLSEC_SUCCESS;
	const char *seed = llsec_gen_random_str_internal(LLSEC_RANDOM_SEED_SIZE);

#if !defined(NO_ASN) && !defined(NO_ASN_TIME)
	// init the time function
	llsec_init_time_function();
#endif

	if (NULL == seed) {
		LLSEC_SIG_DEBUG_TRACE("%s llsec_gen_random_str_internal: allocation error\n", __func__);
		return_code = LLSEC_ERROR;
	}
	if (LLSEC_SUCCESS == return_code) {
		llsec_wc_RNG = wc_rng_new((byte *)seed, (word32)strlen(seed), NULL);
		if (NULL == llsec_wc_RNG) {
			return_code = LLSEC_ERROR;
		}
	}
	return return_code;
}

/**
 * @brief Determines the error message from a Wolfcrypt error code.
 * @param error_code Wolfcrypt error code.
 *
 * @return C string containing the error message.
 */
char const * llsec_wc_error_message(int error_code) {
	char const *error_message;
	switch (error_code) {
	case BAD_FUNC_ARG:
	case BUFFER_E:
		error_message = "LLSEC internal error";
		break;
	case SIG_TYPE_E:
		error_message = "Signature type not enabled/available";
		break;
	default:
		error_message = wc_GetErrorString(error_code);
		break;
	}
	return error_message;
}

/**
 * @brief Generates random string function.
 * @param[in] Length the string length.
 *
 * @return Pointer to random string.
 */
char * llsec_gen_random_str_internal(int length) {
	char *return_code = NULL;
	char *str_ran;
	str_ran = (char *)LLSEC_calloc(1, length);
	if (NULL == str_ran) {
		LLSEC_RANDOM_DEBUG_TRACE("Random string malloc failed");
		while (1) {
		}
		;
	} else {
		srand((unsigned int)microej_time_get_current_time(0));

		int idx;
		for (idx = 0; idx < (length - 1); idx++) {
			int flag = rand() % 3;
			switch (flag) {
			case 0:
				// cppcheck-suppress [misra-c2012-10.8] : Number in [0, 25] range
				str_ran[idx] = 'A' + (uint8_t)(rand() % 26);
				break;
			case 1:
				// cppcheck-suppress [misra-c2012-10.8] : Number in [0, 25] range
				str_ran[idx] = 'a' + (uint8_t)(rand() % 26);
				break;
			case 2:
				// cppcheck-suppress [misra-c2012-10.8] : Number in [0, 10] range
				str_ran[idx] = '0' + (uint8_t)(rand() % 10);
				break;
			default:
				str_ran[idx] = 'x';
				break;
			}
		}
		str_ran[length - 1] = '\0';
		return_code = str_ran;
	}

	return return_code;
}

/**
 * @brief Determines the Wolfcrpyt hashtype value from a LLSEC_RSA_CIPHER_oaep_hash_algorithm value.
 *
 * @return Wolfcrypt hashType enum value.
 */
enum wc_HashType llsec_rsa_get_wc_hash(LLSEC_RSA_CIPHER_oaep_hash_algorithm hash) {
	enum wc_HashType return_value;
	switch (hash) {
	case OAEP_HASH_SHA_1_ALGORITHM:
		return_value = WC_HASH_TYPE_SHA;
		break;
	case OAEP_HASH_SHA_256_ALGORITHM:
		return_value = WC_HASH_TYPE_SHA256;
		break;
	default:
		return_value = WC_HASH_TYPE_NONE;
		break;
	}

	return return_value;
}

/**
 * @brief Determines the Wolfcrpyt padding type value from a LLSEC_RSA_CIPHER_padding_type value.
 *
 * @return Wolfcrypt padding type value.
 */
int  llsec_rsa_get_padding(LLSEC_RSA_CIPHER_padding_type type) {
	int return_value;
	switch (type) {
	case PAD_PKCS1_TYPE:
		return_value = WC_RSA_PKCSV15_PAD;
		break;
	case PAD_OAEP_MGF1_TYPE:
		return_value = WC_RSA_OAEP_PAD;
		break;
	default:
		return_value = WC_RSA_NO_PAD;
		break;
	}

	return return_value;
}

/**
 * @brief Determines the Wolfcrypt curve ID for ECC algorithm, from a standard name.
 * @param stdname C string containing the curve standard name for ECC algorithm.
 *
 * @return Worlfcrypt curve ID.
 */
ecc_curve_id llsec_ecc_get_wc_curve_id(uint8_t *stdname) {
	// standard curve names / ids
	static const char *curve_stdnames[] = {
		"secp192r1",
		"prime192v2",
		"prime192v3",
		"prime239v1",
		"prime239v2",
		"prime239v3",
		"secp256r1",
		"secp112r1",
		"secp112r2",
		"secp128r1",
		"secp128r2",
		"secp160r1",
		"secp160r2",
		"secp224r1",
		"secp384r1",
		"secp521r1",
		"secp160k1",
		"secp192k1",
		"secp224k1",
		"secp256k1",
		"brainpoolp160r1",
		"brainpoolp192r1",
		"brainpoolp224r1",
		"brainpoolp256r1",
		"brainpoolp320r1",
		"brainpoolp384r1",
		"brainpoolp512r1",
		"sm2p256v1",
	};

	static ecc_curve_id curve_ids[] = {
		ECC_SECP192R1,
		ECC_PRIME192V2,
		ECC_PRIME192V3,
		ECC_PRIME239V1,
		ECC_PRIME239V2,
		ECC_PRIME239V3,
		ECC_SECP256R1,
		ECC_SECP112R1,
		ECC_SECP112R2,
		ECC_SECP128R1,
		ECC_SECP128R2,
		ECC_SECP160R1,
		ECC_SECP160R2,
		ECC_SECP224R1,
		ECC_SECP384R1,
		ECC_SECP521R1,
		ECC_SECP160K1,
		ECC_SECP192K1,
		ECC_SECP224K1,
		ECC_SECP256K1,
		ECC_BRAINPOOLP160R1,
		ECC_BRAINPOOLP192R1,
		ECC_BRAINPOOLP224R1,
		ECC_BRAINPOOLP256R1,
		ECC_BRAINPOOLP320R1,
		ECC_BRAINPOOLP384R1,
		ECC_BRAINPOOLP512R1,
		ECC_SM2P256V1,
	};

	uint8_t index;
	ecc_curve_id result = ECC_CURVE_INVALID;
	for (index = 0; index < (sizeof(curve_ids) / sizeof(ecc_curve_id)); index++) {
		if (0 == strcmp((const char *)curve_stdnames[index], (const char *)stdname)) {
			result = curve_ids[index];
		}
	}
	return result;
}

/**
 * @brief Determines the Wolfcrypt hash type ID from the standard name of the algorithm.
 * @param stdname C string containing the name of the hash algorithm.
 *
 * @return Wolfcrypt hash algorithm ID
 */
enum wc_HashType llsec_sign_get_wc_hash_type(uint8_t *stdname) {
	static enum wc_HashType hash_type_ids[] ={
		WC_HASH_TYPE_NONE,
		WC_HASH_TYPE_MD2,
		WC_HASH_TYPE_MD4,
		WC_HASH_TYPE_MD5,
		WC_HASH_TYPE_SHA,
		WC_HASH_TYPE_SHA224,
		WC_HASH_TYPE_SHA256,
		WC_HASH_TYPE_SHA384,
		WC_HASH_TYPE_SHA512,
		WC_HASH_TYPE_MD5_SHA,
		WC_HASH_TYPE_SHA3_224,
		WC_HASH_TYPE_SHA3_256,
		WC_HASH_TYPE_SHA3_384,
		WC_HASH_TYPE_SHA3_512,
		WC_HASH_TYPE_BLAKE2B,
		WC_HASH_TYPE_BLAKE2S,
		#ifndef WOLFSSL_NOSHA512_224
		WC_HASH_TYPE_SHA512_224,
		#endif
		#ifndef WOLFSSL_NOSHA512_256
		WC_HASH_TYPE_SHA512_256,
		#endif
		#ifdef WOLFSSL_SHAKE128
		WC_HASH_TYPE_SHAKE128,
		#endif
		#ifdef WOLFSSL_SHAKE256
		WC_HASH_TYPE_SHAKE25,
		#endif
		#ifdef WOLFSSL_SM3
		WC_HASH_TYPE_SM3,
		#endif
	};

	static const char *hash_type_names[] = {
		"NONE",
		"MD2",
		"MD4",
		"MD5",
		"SHA",
		"SHA224",
		"SHA256",
		"SHA384",
		"SHA512",
		"MD5_SHA",
		"SHA3_224",
		"SHA3_256",
		"SHA3_384",
		"SHA3_512",
		"BLAKE2B",
		"BLAKE2S",
		#ifndef WOLFSSL_NOSHA512_224
		"SHA512_224",
		#endif
		#ifndef WOLFSSL_NOSHA512_256
		"SHA512_256",
		#endif
		#ifdef WOLFSSL_SHAKE128
		"SHAKE128",
		#endif
		#ifdef WOLFSSL_SHAKE256
		"SHAKE25",
		#endif
		#ifdef WOLFSSL_SM3
		"SM3",
		#endif
	};

	uint8_t index;
	enum wc_HashType result = WC_HASH_TYPE_NONE;
	for (index=0; index < (sizeof(hash_type_ids) / sizeof(enum wc_HashType)); index++) {
		if (0 == strcmp((const char *)hash_type_names[index], (const char *)stdname)) {
			result = hash_type_ids[index];
		}
	}
	return result;
}
