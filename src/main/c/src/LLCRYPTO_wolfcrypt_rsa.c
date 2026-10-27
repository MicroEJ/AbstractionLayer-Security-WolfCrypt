/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - RSA functions.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_common.h>
#include <LLCRYPTO_wolfcrypt.h>
#include "LLCRYPTO_ERRORS.h"

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

int32_t llcrypto_wolfcrypt_rsa_generate_key_pair(LLCRYPTO_priv_key *key_pair, int32_t key_size,
                                                 int32_t public_exponent, int *wolfcrypt_rc,
                                                 const char **reason) {
	LLCRYPTO_GENERIC_DEBUG_TRACE("%s(key=%p, key_size=%d, public_exponent=%ld)\n", __func__, (void *)key_pair,
	                             key_size, public_exponent);
	int32_t result = LLCRYPTO_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

	if (LLCRYPTO_SUCCESS == result) {
		if (RSA_MAX_SIZE < key_size) {
			result = LLCRYPTO_ERROR;
			*reason = "RSA key size requested exceeds maximum supported";
		}
	}

	RsaKey *key = NULL;
	if (LLCRYPTO_SUCCESS == result) {
		key = llcrypto_calloc(1, sizeof(RsaKey));
		if (NULL == key) {
			result = LLCRYPTO_ERROR;
			*reason = "Could not allocate RSA key pair";
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		*wolfcrypt_rc = wc_InitRsaKey(key, pHint);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != *wolfcrypt_rc) {
			result = LLCRYPTO_JOB_EXCEPTION;
			*reason = "Could not initialize RSA key pair";
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		*wolfcrypt_rc = wc_MakeRsaKey(key, (int)key_size, (long)public_exponent, llcrypto_wolfcrypt_RNG);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != *wolfcrypt_rc) {
			result = LLCRYPTO_JOB_EXCEPTION;
			*reason = "Could not generate RSA key pair";
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		key_pair->algo_type = ALGO_RSA;
		key_pair->rsa_key = key;
	} else {
		if (NULL != key) {
			wc_FreeRsaKey(key);
			llcrypto_free(key);
		}
	}

	return result;
}

void llcrypto_wolfcrypt_rsa_free(LLCRYPTO_priv_key *key) {
	LLCRYPTO_GENERIC_DEBUG_TRACE("%s(key=%p)\n", __func__, (void *)key);
	LLCRYPTO_ASSERT(key->algo_type == ALGO_RSA);
	wc_FreeRsaKey(key->rsa_key);
	llcrypto_free(key->rsa_key);
}

#endif // NO_RSA

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
