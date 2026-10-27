/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - EC functions.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_common.h>
#include <LLCRYPTO_wolfcrypt.h>
#include "LLCRYPTO_ERRORS.h"

#ifdef HAVE_ECC

// --------------------------------------------------------------------------------
// Variable declarations
// --------------------------------------------------------------------------------

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

// --------------------------------------------------------------------------------
// Public functions
// --------------------------------------------------------------------------------

int32_t llcrypto_wolfcrypt_ec_generate_key_pair(LLCRYPTO_priv_key *key_pair, uint8_t *curve_name,
                                                int *wolfcrypt_rc, const char **reason) {
	LLCRYPTO_GENERIC_DEBUG_TRACE("%s(key_pair=%p, curve_name=%s)\n", __func__, key_pair, curve_name);
	int result = LLCRYPTO_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

	int curve_size;
	if (LLCRYPTO_SUCCESS == result) {
		int curveId = llcrypto_ecc_get_wc_curve_id(curve_name);
		*wolfcrypt_rc = wc_ecc_get_curve_size_from_id(curveId);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS > *wolfcrypt_rc) { // likely ECC_BAD_ARG_E
			result = LLCRYPTO_JOB_EXCEPTION;
			*reason = "EC curve not supported";
		} else {
			curve_size = *wolfcrypt_rc;
		}
	}

	ecc_key *key = NULL;
	if (LLCRYPTO_SUCCESS == result) {
		key = llcrypto_calloc(1, sizeof(ecc_key));
		if (NULL == key) {
			result = LLCRYPTO_ERROR;
			*reason = "Could not allocate EC key pair";
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		*wolfcrypt_rc = wc_ecc_init_ex(key, pHint, INVALID_DEVID);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != *wolfcrypt_rc) {
			result = LLCRYPTO_JOB_EXCEPTION;
			*reason = "Could not initialize EC key pair";
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		*wolfcrypt_rc = wc_ecc_make_key(llcrypto_wolfcrypt_RNG, curve_size, key);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS > *wolfcrypt_rc) {
			result = LLCRYPTO_ERROR;
			*reason = "Could not generate EC key pair";
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		key_pair->algo_type = ALGO_ECDSA;
		key_pair->ec_key = key;
	} else {
		if (NULL != key) {
			wc_ecc_free(key);
			llcrypto_free(key);
		}
	}

	return result;
}

#ifdef WOLF_PRIVATE_KEY_ID
/**
 * Initializes a key from with a label and a device_id (e.g. corresponding to a keystore)
 */
int32_t llcrypto_wolfcrypt_ec_init_label(char *label, LLCRYPTO_key *key, int32_t device_id) {
	LLCRYPTO_GENERIC_DEBUG_TRACE("%s(label=%s, device_id=%d)\n", __func__, label, device_id);

	int32_t ret = LLCRYPTO_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

	if (NULL == key) {
		llcrypto_throw(LLCRYPTO_ERROR, "Invalid key");
	}

	if (LLCRYPTO_SUCCESS == ret) {
		key->ec_key = (ecc_key *)llcrypto_calloc(1, sizeof(ecc_key));

		if (NULL == key->ec_key) {
			LLCRYPTO_GENERIC_DEBUG_TRACE("Could not allocate EC key\n");
			ret = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == ret) {
		int rc = wc_ecc_init_label(key->ec_key, label, pHint, device_id);
		if (0 != rc) {
			LLCRYPTO_GENERIC_DEBUG_TRACE("wc_ecc_init_label failed with error %d\n", rc);
			ret = LLCRYPTO_ERROR;
		}
	}

	if ((LLCRYPTO_SUCCESS != ret) && (NULL != key) && (NULL != key->ec_key)) {
		wc_ecc_free(key->ec_key);
		llcrypto_free(key->ec_key);
	}

	return ret;
}

#endif // WOLF_PRIVATE_KEY_ID

void llcrypto_wolfcrypt_ec_free(LLCRYPTO_priv_key *key) {
	LLCRYPTO_GENERIC_DEBUG_TRACE("%s(key=%p)\n", __func__, key);
	LLCRYPTO_ASSERT(key->algo_type == ALGO_ECDSA);
	wc_ecc_free(key->ec_key);
	llcrypto_free(key->ec_key);
}

#endif // HAVE_ECC

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
