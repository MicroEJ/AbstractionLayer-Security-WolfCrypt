/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Private key PKCS8 encoding.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_ERRORS.h>
#include <LLSEC_PRIVATE_KEY_impl.h>
#include <LLSEC_wolfcrypt.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------------
// LLSEC_PRIVATE_KEY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_PRIVATE_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLSEC_PRIVATE_KEY_DEBUG_TRACE("%s \n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_priv_key *key = (LLSEC_priv_key *)native_id;

	int return_code = LLSEC_ERROR;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	if (TYPE_RSA == key->key_type) {
		return_code = 8 * (RSA_MAX_SIZE / 8);
	} else { // TYPE_ECDSA
		wolfcrypt_rc = wc_EccKeyDerSize((ecc_key *)key->key, 1);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			LLSEC_PRIVATE_KEY_DEBUG_TRACE("wc_EccKeyDerSize() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
			(void)SNI_throwNativeException(wolfcrypt_rc, "Could not get size of ECDSA private key DER");
		} else {
			return_code = wolfcrypt_rc;
		}
	}
	LLSEC_PRIVATE_KEY_DEBUG_TRACE("%s() => %d\n", __func__, return_code);
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_PRIVATE_KEY_IMPL_get_encode(int32_t native_id, uint8_t *output, int32_t outputLength) {
	LLSEC_PRIVATE_KEY_DEBUG_TRACE("%s\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_priv_key *key = (LLSEC_priv_key *)native_id;

	int return_code = LLSEC_ERROR;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	if (TYPE_RSA == key->key_type) {
		wolfcrypt_rc = wc_RsaKeyToDer((RsaKey *)key->key, output, outputLength);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			LLSEC_PRIVATE_KEY_DEBUG_TRACE("wc_RsaKeyToDer() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
			(void)SNI_throwNativeException(wolfcrypt_rc, "Could not encode RSA private key to DER");
		} else {
			return_code = wolfcrypt_rc;
		}
	} else { // TYPE_ECDSA
		wolfcrypt_rc = wc_EccKeyToDer((ecc_key *)key->key, output, outputLength);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			LLSEC_PRIVATE_KEY_DEBUG_TRACE("wc_EccKeyToDer() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
			(void)SNI_throwNativeException(wolfcrypt_rc, "Could not encode ECDSA private key to DER");
		} else {
			return_code = wolfcrypt_rc;
		}
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_PRIVATE_KEY_IMPL_get_output_size(int32_t native_id) {
	LLSEC_PRIVATE_KEY_DEBUG_TRACE("%s\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_pub_key *key = (LLSEC_pub_key *)native_id;

	int return_code = LLSEC_ERROR;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	if (TYPE_RSA == key->key_type) {
		wolfcrypt_rc = wc_RsaEncryptSize((RsaKey *)key->key);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			LLSEC_PRIVATE_KEY_DEBUG_TRACE("wc_RsaEncryptSize() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
			(void)SNI_throwNativeException(wolfcrypt_rc, "Output buffer size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
	} else { // TYPE_ECDSA
		wolfcrypt_rc = wc_ecc_sig_size((ecc_key *)key->key);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			LLSEC_PRIVATE_KEY_DEBUG_TRACE("wc_ecc_sig_size() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
			(void)SNI_throwNativeException(wolfcrypt_rc, "Output buffer size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
	}
	return return_code;
}
