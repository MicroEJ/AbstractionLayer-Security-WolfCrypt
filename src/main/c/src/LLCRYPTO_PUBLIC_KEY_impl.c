/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - Public key PKCS8 encoding.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_ERRORS.h>
#include <LLCRYPTO_PUBLIC_KEY_impl.h>
#include <LLCRYPTO_wolfcrypt.h>
#include <LLCRYPTO_common.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------------
// LLCRYPTO_PUBLIC_KEY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLCRYPTO_PUBLIC_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLCRYPTO_PUBLIC_KEY_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_pub_key *key = (LLCRYPTO_pub_key *)native_id;

	int return_code = LLCRYPTO_ERROR;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;

	switch (key->algo_type) {
#ifndef NO_RSA
	case ALGO_RSA:
		wolfcrypt_rc = wc_RsaPublicKeyDerSize(key->rsa_key, 1);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			llcrypto_throw(wolfcrypt_rc, "Encoded key max size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
		break;
#endif // NO_RSA
	case ALGO_ECDSA:
		if (NULL != key->ec_key->dp) {
			wolfcrypt_rc = wc_EccPublicKeyDerSize(key->ec_key, 1);
			if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
				llcrypto_throw(wolfcrypt_rc, "Encoded key max size get failed");
			} else {
				return_code = wolfcrypt_rc;
			}
		} else {
			llcrypto_throw(LLCRYPTO_ERROR, "Key no retrievable");
		}
		break;
	default:
		llcrypto_throw(LLCRYPTO_ERROR, "Unsupported key type");
		break;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_PUBLIC_KEY_IMPL_get_encode(int32_t native_id, uint8_t *output, int32_t outputLength) {
	LLCRYPTO_PUBLIC_KEY_DEBUG_TRACE("%s \n", __func__);
	int return_code = LLCRYPTO_ERROR;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_pub_key *key = (LLCRYPTO_pub_key *)native_id;

	switch (key->algo_type) {
#ifndef NO_RSA
	case ALGO_RSA:
		wolfcrypt_rc = wc_RsaKeyToPublicDer(key->rsa_key, output, outputLength);
		if (MEMORY_E == wolfcrypt_rc) {
			/* Returned, not thrown: the Crypto library runs a garbage collection and retries on this code. */
			return_code = LLCRYPTO_ERROR_OOM;
		} else if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			llcrypto_throw(wolfcrypt_rc, "Public key encoding failed");
		} else {
			return_code = wolfcrypt_rc;
		}
		break;
#endif // NO_RSA
	case ALGO_ECDSA:
		if (NULL != key->ec_key->dp) {
			wolfcrypt_rc = wc_EccPublicKeyToDer(key->ec_key, output, outputLength, 1);
			if (MEMORY_E == wolfcrypt_rc) {
				/* Returned, not thrown: the Crypto library runs a garbage collection and retries on this code. */
				return_code = LLCRYPTO_ERROR_OOM;
			} else if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
				llcrypto_throw(wolfcrypt_rc, "Public key encoding failed");
			} else {
				return_code = wolfcrypt_rc;
			}
		} else {
			llcrypto_throw(LLCRYPTO_ERROR, "Key no retrievable");
		}
		break;
	default:
		// it should never happen
		break;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_PUBLIC_KEY_IMPL_get_output_size(int32_t native_id) {
	LLCRYPTO_PUBLIC_KEY_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_pub_key *key = (LLCRYPTO_pub_key *)native_id;

	int return_code = LLCRYPTO_ERROR;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;

	switch (key->algo_type) {
#ifndef NO_RSA
	case ALGO_RSA:
		wolfcrypt_rc = wc_RsaEncryptSize(key->rsa_key);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			llcrypto_throw(wolfcrypt_rc, "Output buffer size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
		break;
#endif // NO_RSA
	case ALGO_ECDSA:
		if (NULL != key->ec_key->dp) {
			wolfcrypt_rc = wc_ecc_size(key->ec_key);
			if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
				llcrypto_throw(wolfcrypt_rc, "Output buffer size get failed");
			} else {
				return_code = wolfcrypt_rc;
			}
		} else {
			llcrypto_throw(LLCRYPTO_ERROR, "Key no retrievable");
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
