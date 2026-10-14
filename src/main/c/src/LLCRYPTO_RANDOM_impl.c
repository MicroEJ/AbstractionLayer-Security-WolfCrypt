/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - Pseudo Random Number Generators.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_ERRORS.h>
#include <LLCRYPTO_RANDOM_impl.h>
#include <microej_time.h>
#include <LLCRYPTO_wolfcrypt.h>
#include <LLCRYPTO_common.h>

#include <sni.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------------
// LLCRYPTO_RANDOM_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLCRYPTO_RANDOM_IMPL_init(void) {
	LLCRYPTO_RANDOM_DEBUG_TRACE("%s()\n", __func__);
	int32_t return_code = LLCRYPTO_SUCCESS;
	int32_t native_id;
	WC_RNG *wolfcrypt_rng = NULL;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

	int nonce_size = LLCRYPTO_RANDOM_SEED_SIZE;
	char *nonce = llcrypto_gen_random_str_internal(nonce_size);
	if (NULL == nonce) {
		llcrypto_throw(LLCRYPTO_ERROR_OOM, "Could not allocate seed buffer");
		return_code = LLCRYPTO_ERROR;
	} else {
		wolfcrypt_rng = wc_rng_new((byte *)nonce, (word32)nonce_size, pHint);
		if (NULL == wolfcrypt_rng) {
			llcrypto_throw(LLCRYPTO_ERROR, "Could not initialize RNG");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		native_id = (int32_t)wolfcrypt_rng;

		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		if (SNI_OK != SNI_registerResource((void *)native_id, (SNI_closeFunction)LLCRYPTO_RANDOM_IMPL_close, NULL)) {
			llcrypto_throw(LLCRYPTO_ERROR, "Could not register SNI native resource");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (NULL != nonce) {
		llcrypto_free((void *)nonce);
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		return_code = native_id;
	} else {
		return_code = SNI_IGNORED_RETURNED_VALUE;
		if (NULL != wolfcrypt_rng) {
			wc_rng_free(wolfcrypt_rng);
		}
	}

	LLCRYPTO_RANDOM_DEBUG_TRACE("%s() => %d\n", __func__, return_code);
	return return_code;
}

// See the header file for the function documentation
// cppcheck-suppress [misra-c2012-8.7]: API function that can be used in another file.
void LLCRYPTO_RANDOM_IMPL_close(int32_t native_id) {
	LLCRYPTO_RANDOM_DEBUG_TRACE("%s(id=%d)\n", __func__, native_id);

	WC_RNG *wolfcrypt_rng = (WC_RNG *)native_id;
	wc_rng_free(wolfcrypt_rng);
}

// See the header file for the function documentation
// cppcheck-suppress [misra-c2012-8.7]: API function that can be used in another file.
void LLCRYPTO_RANDOM_IMPL_next_bytes(int32_t native_id, uint8_t *rnd, int32_t size) {
	LLCRYPTO_RANDOM_DEBUG_TRACE("%s(id=%d, size=%d)\n", __func__, native_id, size);
	WC_RNG *wolfcrypt_rng = (WC_RNG *)native_id;
	uint32_t bytes_left = (uint32_t)size;
	uint32_t rnd_index = 0;

	bool is_leaving_loop = false;
	while (((uint32_t)0 < bytes_left) && !is_leaving_loop) {
		int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
		if ((uint32_t)RNG_MAX_BLOCK_LEN < bytes_left) {
			wolfcrypt_rc = wc_RNG_GenerateBlock(wolfcrypt_rng, &rnd[rnd_index], RNG_MAX_BLOCK_LEN);
			bytes_left -= (uint32_t)RNG_MAX_BLOCK_LEN;
			rnd_index += RNG_MAX_BLOCK_LEN;
		} else {
			wolfcrypt_rc = wc_RNG_GenerateBlock(wolfcrypt_rng, &rnd[rnd_index], bytes_left);
			bytes_left = 0;
		}
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			LLCRYPTO_RANDOM_DEBUG_TRACE("wc_RNG_GenerateBlock() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
#ifdef HAVE_HASHDRBG
			if (RNG_FAILURE_E == wolfcrypt_rc) { // failed to re-seed itself (no entropy source configured?)
				LLCRYPTO_RANDOM_DEBUG_TRACE("Re-seeding...");
				int entropy_size = LLCRYPTO_RANDOM_SEED_SIZE;
				char *entropy = llcrypto_gen_random_str_internal(entropy_size);
				if (NULL == entropy) {
					LLCRYPTO_RANDOM_DEBUG_TRACE(
						"llcrypto_gen_random_str_internal() failed, keep RNG_FAILURE_E error\n");
				} else {
					wolfcrypt_rc = wc_RNG_DRBG_Reseed(wolfcrypt_rng, (byte *)entropy, (word32)entropy_size);
					llcrypto_free((void *)entropy);
					if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
						LLCRYPTO_RANDOM_DEBUG_TRACE("wc_RNG_DRBG_Reseed() failed: %s\n",
						                            wc_GetErrorString(wolfcrypt_rc));
						llcrypto_throw(wolfcrypt_rc, "Could not re-seed random number generator");
						break;
					}
				}
			}
#endif
			llcrypto_throw(wolfcrypt_rc, "Could not generate more random bytes");
			is_leaving_loop = true;
		}
	}
}

// See the header file for the function documentation
void LLCRYPTO_RANDOM_IMPL_set_seed(int32_t native_id, uint8_t *seed, int32_t size) {
	LLCRYPTO_RANDOM_DEBUG_TRACE("%s(id=%d, size=%d)\n", __func__, native_id, size);
	WC_RNG *wolfcrypt_rng = (WC_RNG *)native_id;
	int wolfcrypt_rc = wc_RNG_DRBG_Reseed(wolfcrypt_rng, (byte *)seed, (word32)size);
	if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		LLCRYPTO_RANDOM_DEBUG_TRACE("wc_RNG_DRBG_Reseed() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
		llcrypto_throw(wolfcrypt_rc, "Could not re-seed random number generator");
	}
}

// See the header file for the function documentation
// cppcheck-suppress [misra-c2012-2.7] : false positive, parameters used in optional debug trace and available for other
// implemenations.
void LLCRYPTO_RANDOM_IMPL_generate_seed(int32_t native_id, uint8_t *seed, int32_t size) {
	LLCRYPTO_RANDOM_DEBUG_TRACE("%s(id=%d, size=%d)\n", __func__, native_id, size);
	LLCRYPTO_RANDOM_IMPL_next_bytes(native_id, seed, size);
}

// See the header file for the function documentation
int32_t LLCRYPTO_RANDOM_IMPL_get_close_id(void) {
	LLCRYPTO_RANDOM_DEBUG_TRACE("%s\n", __func__);
	return (int32_t)LLCRYPTO_RANDOM_IMPL_close;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
