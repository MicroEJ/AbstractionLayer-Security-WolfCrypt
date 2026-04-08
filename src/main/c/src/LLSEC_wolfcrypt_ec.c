/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - EC functions.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_common.h>
#include <LLSEC_wolfcrypt.h>
#include "LLSEC_ERRORS.h"

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

int32_t llsec_wolfcrypt_ec_generate_key_pair(LLSEC_priv_key *key_pair, uint8_t *curve_name,
                                             int *wolfcrypt_rc, const char **reason) {
	LLSEC_GENERIC_DEBUG_TRACE("%s(key_pair=%p, curve_name=%s)\n", __func__, key_pair, curve_name);
	int result = LLSEC_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llsec_wolfssl_get_heap();

	int curve_size;
	if (LLSEC_SUCCESS == result) {
		int curveId = llsec_ecc_get_wc_curve_id(curve_name);
		*wolfcrypt_rc = wc_ecc_get_curve_size_from_id(curveId);
		if (LLSEC_WOLFCRYPT_SUCCESS > *wolfcrypt_rc) { // likely ECC_BAD_ARG_E
			result = LLSEC_ERROR_EXCEPTION;
			*reason = "EC curve not supported";
		} else {
			curve_size = *wolfcrypt_rc;
		}
	}

	ecc_key *key = NULL;
	if (LLSEC_SUCCESS == result) {
		key = llsec_calloc(1, sizeof(ecc_key));
		if (NULL == key) {
			result = LLSEC_ERROR;
			*reason = "Could not allocate EC key pair";
		}
	}

	if (LLSEC_SUCCESS == result) {
		*wolfcrypt_rc = wc_ecc_init_ex(key, pHint, INVALID_DEVID);
		if (LLSEC_WOLFCRYPT_SUCCESS != *wolfcrypt_rc) {
			result = LLSEC_ERROR_EXCEPTION;
			*reason = "Could not initialize EC key pair";
		}
	}

	if (LLSEC_SUCCESS == result) {
		*wolfcrypt_rc = wc_ecc_make_key(llsec_wolfcrypt_RNG, curve_size, key);
		if (LLSEC_WOLFCRYPT_SUCCESS > *wolfcrypt_rc) {
			result = LLSEC_ERROR;
			*reason = "Could not generate EC key pair";
		}
	}

	if (LLSEC_SUCCESS == result) {
		key_pair->algo_type = ALGO_ECDSA;
		key_pair->ec_key = key;
	} else {
		if (NULL != key) {
			wc_ecc_free(key);
			llsec_free(key);
		}
	}

	return result;
}

/**
 * Initializes a key from with a label and a device_id (e.g. corresponding to a keystore)
 */
int32_t llsec_wolfcrypt_ec_init_label(char *label, LLSEC_key *key, int32_t device_id) {
	LLSEC_GENERIC_DEBUG_TRACE("%s(label=%s, device_id=%d)\n", __func__, label, device_id);

	int32_t ret = LLSEC_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llsec_wolfssl_get_heap();

	if (NULL == key) {
		llsec_throw(LLSEC_ERROR, "Invalid key");
	}

	if (LLSEC_SUCCESS == ret) {
		key->ec_key = (ecc_key *)llsec_calloc(1, sizeof(ecc_key));

		if (NULL == key->ec_key) {
			LLSEC_GENERIC_DEBUG_TRACE("Could not allocate EC key\n");
			ret = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == ret) {
		int rc = wc_ecc_init_label(key->ec_key, label, pHint, device_id);
		if (0 != rc) {
			LLSEC_GENERIC_DEBUG_TRACE("wc_ecc_init_label failed with error %d\n", rc);
			ret = LLSEC_ERROR;
		}
	}

	if ((LLSEC_SUCCESS != ret) && (NULL != key) && (NULL != key->ec_key)) {
		wc_ecc_free(key->ec_key);
		llsec_free(key->ec_key);
	}

	return ret;
}

void llsec_wolfcrypt_ec_free(LLSEC_priv_key *key) {
	LLSEC_GENERIC_DEBUG_TRACE("%s(key=%p)\n", __func__, key);
	LLSEC_ASSERT(key->algo_type == ALGO_ECDSA);
	wc_ecc_free(key->ec_key);
	llsec_free(key->ec_key);
}

#endif // HAVE_ECC

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
