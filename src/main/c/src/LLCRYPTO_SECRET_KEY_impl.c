/*
 * C
 *
 * Copyright 2023-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief MicroEJ Crypto low level API
 * @author MicroEJ Developer Team
 * @version 2.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_SECRET_KEY_impl.h>
#include <LLCRYPTO_wolfcrypt.h>
#include <LLCRYPTO_common.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <string.h>

// -----------------------------------------------------------------------------
// Private functions
// -----------------------------------------------------------------------------

/**
 * @brief Releases the memory targeted by the input pointer from the WolfSSL heap.
 *
 * @param[in] native_id Pointer of the LLCRYPTO_KEY resource to release.
 */
static void llcrypto_secret_key_close(void *native_id) {
	if (NULL != native_id) {
		LLCRYPTO_key *key = (LLCRYPTO_key *)native_id;
		LLCRYPTO_secret_key *secret_key = key->secret_key;

		if (NULL != secret_key) {
			if (NULL != secret_key->key) {
				/* Wipe the raw key material before releasing its memory (CWE-226). wc_ForceZero() is not
				 * removed by the optimizer as a dead store, unlike a plain memset() before free(). */
				if (secret_key->key_length > 0) {
					wc_ForceZero(secret_key->key, (size_t)secret_key->key_length);
				}
				llcrypto_free(secret_key->key);
			}
			llcrypto_free(secret_key);
		}

		llcrypto_free(key);
	}
}

// --------------------------------------------------------------------------------
// LLCRYPTO_SECRET_KEY_impl.h functions
// --------------------------------------------------------------------------------

// LLAPI: see LLCRYPTO_SECRET_KEY_IMPL.h for definition
int32_t LLCRYPTO_SECRET_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLCRYPTO_SECRET_KEY_DEBUG_TRACE("%s (native_id = %d)\n", __func__, (int)native_id);
	int32_t max_size = 0;

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	const LLCRYPTO_secret_key *secret_key = ((LLCRYPTO_key *)native_id)->secret_key;
	if (NULL != secret_key) {
		max_size = secret_key->key_length;
	}

	LLCRYPTO_SECRET_KEY_DEBUG_TRACE("%s Return size = %d\n", __func__, (int)max_size);
	return max_size;
}

// LLAPI: see LLCRYPTO_SECRET_KEY_IMPL.h for definition
int32_t LLCRYPTO_SECRET_KEY_IMPL_get_encoded(int32_t native_id, uint8_t *output, int32_t output_length) {
	LLCRYPTO_SECRET_KEY_DEBUG_TRACE("%s (native_id = %d)\n", __func__, (int)native_id);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	const LLCRYPTO_secret_key *secret_key = ((LLCRYPTO_key *)native_id)->secret_key;
	if (NULL != secret_key) {
		llcrypto_memcpy(output, secret_key->key, output_length);
	}

	LLCRYPTO_SECRET_KEY_DEBUG_TRACE("%s Return size = %d\n", __func__, (int)output_length);
	return output_length;
}

// LLAPI: see LLCRYPTO_SECRET_KEY_IMPL.h for definition
int32_t LLCRYPTO_SECRET_KEY_IMPL_create(uint8_t *raw_key, int32_t raw_key_length, uint8_t *algorithm) {
	LLCRYPTO_SECRET_KEY_DEBUG_TRACE("%s \n", __func__);

	/* Every failure throws a native exception, so the value returned on failure is ignored by the VM. */
	int32_t result = LLCRYPTO_SUCCESS;
	LLCRYPTO_secret_key *secret_key_struct = NULL;

	LLCRYPTO_key *key = llcrypto_calloc(1, sizeof(LLCRYPTO_key));
	if (NULL == key) {
		llcrypto_throw(LLCRYPTO_ERROR_OOM, "Cannot allocate key structure");
		result = LLCRYPTO_ERROR;
	}

	if (LLCRYPTO_SUCCESS == result) {
		secret_key_struct = (LLCRYPTO_secret_key *)llcrypto_calloc(1, sizeof(LLCRYPTO_secret_key));
		if (NULL == secret_key_struct) {
			llcrypto_throw(LLCRYPTO_ERROR_OOM, "Cannot allocate secret key structure");
			result = LLCRYPTO_ERROR;
		} else {
			key->secret_key = secret_key_struct;
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
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
			llcrypto_throw(LLCRYPTO_ERROR, "Unknown algorithm");
			result = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		void *secret_raw_key = llcrypto_calloc(raw_key_length, sizeof(uint8_t));
		if (NULL == secret_raw_key) {
			llcrypto_throw(LLCRYPTO_ERROR_OOM, "Cannot allocate key buffer");
			result = LLCRYPTO_ERROR;
		} else {
			key->secret_key->key = (uint8_t *)secret_raw_key;
			llcrypto_memcpy(key->secret_key->key, raw_key, raw_key_length);
			key->secret_key->key_length = raw_key_length;
			key->key_type = LLCRYPTO_KEY_TYPE_SECRET;
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		if (SNI_OK != SNI_registerResource((void *)key, (SNI_closeFunction)llcrypto_secret_key_close,
		                                   NULL)) {
			llcrypto_secret_key_close(key);
			result = LLCRYPTO_ERROR;
			LLCRYPTO_EXTERNAL_KEYSTORE_DEBUG_TRACE("%s, Cannot register native resource ; code=%d \n", __func__,
			                                       result);
		} else {
			result = (jint)key;
		}
	} else {
		/* The key material is only allocated once the earlier steps succeeded: nothing else to release. */
		llcrypto_free(secret_key_struct);
		llcrypto_free(key);
	}
	return result;
}

// LLAPI: see LLCRYPTO_SECRET_KEY_IMPL.h for definition
int32_t LLCRYPTO_SECRET_KEY_IMPL_nativeGetCloseId(void) {
	LLCRYPTO_SECRET_KEY_DEBUG_TRACE("%s ; llcrypto_secret_key_close symbol addr = 0x%p \n", __func__,
	                                llcrypto_secret_key_close);
	return (int32_t)llcrypto_secret_key_close;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
