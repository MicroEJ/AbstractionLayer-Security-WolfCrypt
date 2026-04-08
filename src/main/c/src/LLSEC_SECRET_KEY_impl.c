/*
 * C
 *
 * Copyright 2023-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief MicroEJ Security low level API
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_SECRET_KEY_impl.h>
#include <LLSEC_wolfcrypt.h>
#include <LLSEC_common.h>

#include <string.h>

// -----------------------------------------------------------------------------
// Private functions
// -----------------------------------------------------------------------------

/**
 * @brief Releases the memory targeted by the input pointer from the WolfSSL heap.
 *
 * @param[in] native_id Pointer of the LLSEC_KEY resource to release.
 */
static void llsec_secret_key_close(void *native_id) {
	if (NULL != native_id) {
		LLSEC_key *key = (LLSEC_key *)native_id;
		LLSEC_secret_key *secret_key = key->secret_key;
		uint8_t *buf = (uint8_t *)secret_key->key;

		if (NULL != buf) {
			llsec_free(buf);
		}

		if (NULL != secret_key) {
			llsec_free(secret_key);
		}

		if (NULL != key) {
			llsec_free(key);
		}
	}
}

// --------------------------------------------------------------------------------
// LLSEC_SECRET_KEY_impl.h functions
// --------------------------------------------------------------------------------

// LLAPI: see LLSEC_SECRET_KEY_IMPL.h for definition
int32_t LLSEC_SECRET_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLSEC_SECRET_KEY_DEBUG_TRACE("%s (native_id = %d)\n", __func__, (int)native_id);
	int32_t max_size = 0;

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	const LLSEC_secret_key *secret_key = (LLSEC_secret_key *)native_id;
	if (NULL != secret_key) {
		max_size = secret_key->key_length;
	}

	LLSEC_SECRET_KEY_DEBUG_TRACE("%s Return size = %d\n", __func__, (int)max_size);
	return max_size;
}

// LLAPI: see LLSEC_SECRET_KEY_IMPL.h for definition
int32_t LLSEC_SECRET_KEY_IMPL_get_encoded(int32_t native_id, uint8_t *output, int32_t output_length) {
	LLSEC_SECRET_KEY_DEBUG_TRACE("%s (native_id = %d)\n", __func__, (int)native_id);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	const LLSEC_secret_key *secret_key = (LLSEC_secret_key *)native_id;
	if (NULL != secret_key) {
		llsec_memcpy(output, secret_key->key, output_length);
	}

	LLSEC_SECRET_KEY_DEBUG_TRACE("%s Return size = %d\n", __func__, (int)output_length);
	return output_length;
}

// LLAPI: see LLSEC_SECRET_KEY_IMPL.h for definition
int32_t LLSEC_SECRET_KEY_IMPL_create(uint8_t *raw_key, int32_t raw_key_length, uint8_t *algorithm) {
	LLSEC_SECRET_KEY_DEBUG_TRACE("%s \n", __func__);

	int32_t result = LLSEC_SUCCESS;

	LLSEC_key *key = llsec_calloc(1, sizeof(LLSEC_key));
	key->secret_key = (LLSEC_secret_key *)llsec_calloc(1, sizeof(LLSEC_secret_key));

	if (strcmp((char const *)algorithm, "AES") == 0) {
		key->algo_type = ALGO_AES;
	} else if (strcmp((char const *)algorithm, "RSA") == 0) {
		key->algo_type = ALGO_RSA;
	} else if (strcmp((char const *)algorithm, "EC") == 0) {
		key->algo_type = ALGO_ECDSA;
	} else if (strcmp((char const *)algorithm, "NULL") == 0) {
		// According to the spec, can be safely ignored if null.
		key->algo_type = ALGO_NONE;
	} else { // default:
		llsec_throw(LLSEC_ERROR, "Unknown algorithm");
		result = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == result) {
		void *secret_raw_key = llsec_calloc(raw_key_length, sizeof(uint8_t));
		key->secret_key->key = (uint8_t *)secret_raw_key;
		llsec_memcpy(key->secret_key->key, raw_key, raw_key_length);
		key->secret_key->key_length = raw_key_length;
		key->key_type = LLSEC_KEY_TYPE_SECRET;
	}

	if (result == LLSEC_SUCCESS) {
		if (SNI_OK != SNI_registerResource((void *)key, (SNI_closeFunction)llsec_secret_key_close,
		                                   NULL)) {
			llsec_secret_key_close(key);
			result = LLSEC_ERROR;
			LLSEC_EXTERNAL_KEYSTORE_DEBUG_TRACE("%s, Cannot register native resource ; code=%d \n", __func__, result);
		} else {
			result = (jint)key;
		}
	}
	return result;
}

// LLAPI: see LLSEC_SECRET_KEY_IMPL.h for definition
int32_t LLSEC_SECRET_KEY_IMPL_nativeGetCloseId(void) {
	LLSEC_SECRET_KEY_DEBUG_TRACE("%s ; llsec_secret_key_close symbol addr = 0x%p \n", __func__, llsec_secret_key_close);
	return (int32_t)llsec_secret_key_close;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
