/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Public key PKCS8 encoding.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_ERRORS.h>
#include <LLSEC_PUBLIC_KEY_impl.h>
#include <LLSEC_wolfcrypt.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------------
// LLSEC_PUBLIC_KEY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_PUBLIC_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLSEC_PUBLIC_KEY_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_pub_key *key = (LLSEC_pub_key *)native_id;

	int return_code = LLSEC_ERROR;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	switch (key->algo_type) {
#ifndef NO_RSA
	case ALGO_RSA:
		wolfcrypt_rc = wc_RsaPublicKeyDerSize(key->rsa_key, 1);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			llsec_throw(wolfcrypt_rc, "Encoded key max size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
		break;
#endif // NO_RSA
	case ALGO_ECDSA:
		wolfcrypt_rc = wc_EccPublicKeyDerSize(key->ec_key, 1);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			llsec_throw(wolfcrypt_rc, "Encoded key max size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
		break;
	default:
		llsec_throw(LLSEC_ERROR, "Unsupported key type");
		break;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_PUBLIC_KEY_IMPL_get_encode(int32_t native_id, uint8_t *output, int32_t outputLength) {
	LLSEC_PUBLIC_KEY_DEBUG_TRACE("%s \n", __func__);
	int return_code = LLSEC_ERROR;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_pub_key *key = (LLSEC_pub_key *)native_id;

	switch (key->algo_type) {
#ifndef NO_RSA
	case ALGO_RSA:
		wolfcrypt_rc = wc_RsaKeyToPublicDer(key->rsa_key, output, outputLength);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			llsec_throw(wolfcrypt_rc, "Public key encoding failed");
		} else {
			return_code = wolfcrypt_rc;
		}
		break;
#endif // NO_RSA
	case ALGO_ECDSA:
		wolfcrypt_rc = wc_EccPublicKeyToDer(key->ec_key, output, outputLength, 1);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			llsec_throw(wolfcrypt_rc, "Public key encoding failed");
		} else {
			return_code = wolfcrypt_rc;
		}
		break;
	default:
		// it should never happen
		break;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_PUBLIC_KEY_IMPL_get_output_size(int32_t native_id) {
	LLSEC_PUBLIC_KEY_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_pub_key *key = (LLSEC_pub_key *)native_id;

	int return_code = LLSEC_ERROR;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	switch (key->algo_type) {
#ifndef NO_RSA
	case ALGO_RSA:
		wolfcrypt_rc = wc_RsaEncryptSize(key->rsa_key);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			llsec_throw(wolfcrypt_rc, "Output buffer size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
		break;
#endif // NO_RSA
	case ALGO_ECDSA:
		wolfcrypt_rc = wc_ecc_size(key->ec_key);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			llsec_throw(wolfcrypt_rc, "Output buffer size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
		break;
	default:
		// it should never happen
		break;
	}
	return return_code;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
