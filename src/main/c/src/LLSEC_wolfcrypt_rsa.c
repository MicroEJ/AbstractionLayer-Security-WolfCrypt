/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - RSA functions.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_common.h>
#include <LLSEC_wolfcrypt.h>
#include "LLSEC_ERRORS.h"

#ifndef NO_RSA

// --------------------------------------------------------------------------------
// Variable declarations
// --------------------------------------------------------------------------------

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

// --------------------------------------------------------------------------------
// Public functions
// --------------------------------------------------------------------------------

int32_t llsec_wolfcrypt_rsa_generate_key_pair(LLSEC_priv_key *key_pair, int32_t key_size,
                                              int32_t public_exponent, int *wolfcrypt_rc,
                                              const char **reason) {
	LLSEC_RSA_CIPHER_DEBUG("%s(key=%p, key_size=%d, public_exponent=%ld)\n", __func__, key, key_size,
	                       public_exponent);
	int32_t result = LLSEC_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llsec_wolfssl_get_heap();

	if (LLSEC_SUCCESS == result) {
		if (RSA_MAX_SIZE < key_size) {
			result = LLSEC_ERROR;
			*reason = "RSA key size requested exceeds maximum supported";
		}
	}

	RsaKey *key = NULL;
	if (LLSEC_SUCCESS == result) {
		key = llsec_calloc(1, sizeof(RsaKey));
		if (NULL == key) {
			result = LLSEC_ERROR;
			*reason = "Could not allocate RSA key pair";
		}
	}

	if (LLSEC_SUCCESS == result) {
		*wolfcrypt_rc = wc_InitRsaKey(key, pHint);
		if (LLSEC_WOLFCRYPT_SUCCESS != *wolfcrypt_rc) {
			result = LLSEC_ERROR_EXCEPTION;
			*reason = "Could not initialize RSA key pair";
		}
	}

	if (LLSEC_SUCCESS == result) {
		*wolfcrypt_rc = wc_MakeRsaKey(key, (int)key_size, (long)public_exponent, llsec_wolfcrypt_RNG);
		if (LLSEC_WOLFCRYPT_SUCCESS != *wolfcrypt_rc) {
			result = LLSEC_ERROR_EXCEPTION;
			*reason = "Could not generate RSA key pair";
		}
	}

	if (LLSEC_SUCCESS == result) {
		key_pair->algo_type = ALGO_RSA;
		key_pair->rsa_key = key;
	} else {
		if (NULL != key) {
			wc_FreeRsaKey(key);
			llsec_free(key);
		}
	}

	return result;
}

void llsec_wolfcrypt_rsa_free(LLSEC_priv_key *key) {
	LLSEC_RSA_CIPHER_DEBUG("%s(key=%p)\n", __func__, key);
	LLSEC_ASSERT(key->algo_type == ALGO_RSA);
	wc_FreeRsaKey(key->rsa_key);
	llsec_free(key->rsa_key);
}

#endif // NO_RSA

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
