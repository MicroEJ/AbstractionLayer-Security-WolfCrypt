/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Pseudo Random Number Generators.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_ERRORS.h>
#include <LLSEC_RANDOM_impl.h>
#include <microej_time.h>
#include <LLSEC_wolfcrypt.h>

#include <sni.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

// --------------------------------------------------------------------------------
// LLSEC_RANDOM_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_RANDOM_IMPL_init(void) {
	LLSEC_RANDOM_DEBUG_TRACE("%s()\n", __func__);
	int32_t return_code = LLSEC_SUCCESS;
	int32_t native_id;
	int32_t wolfcrypt_rc = 0;
	WC_RNG *wolfcrypt_rng = NULL;

	int nonce_size = LLSEC_RANDOM_SEED_SIZE;
	char *nonce = llsec_gen_random_str_internal(nonce_size);
	if (NULL == nonce) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "Could not allocate seed buffer");
		return_code = LLSEC_ERROR;
	} else {
		wolfcrypt_rng = wc_rng_new((byte *)nonce, (word32)nonce_size, NULL);
	}

	if (LLSEC_SUCCESS == return_code) {
		native_id = (int32_t)wolfcrypt_rng;

		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		if (SNI_OK != SNI_registerResource((void *)native_id, (SNI_closeFunction)LLSEC_RANDOM_IMPL_close, NULL)) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Could not register SNI native resource");
			return_code = LLSEC_ERROR;
		}
	}

	if (NULL != nonce) {
		LLSEC_free((void *)nonce);
	}

	if (LLSEC_SUCCESS == return_code) {
		return_code = native_id;
		LLSEC_RANDOM_DEBUG_TRACE("%s() => %d\n", __func__, native_id);
	} else {
		if (NULL != wolfcrypt_rng) {
			wc_rng_free(wolfcrypt_rng);
		}
	}

	return return_code;
}

// See the header file for the function documentation
// cppcheck-suppress [misra-c2012-8.7]: API function that can be used in another file.
void LLSEC_RANDOM_IMPL_close(int32_t native_id) {
	LLSEC_RANDOM_DEBUG_TRACE("%s(id=%d)\n", __func__, native_id);

	WC_RNG *wolfcrypt_rng = (WC_RNG *)native_id;
	wc_rng_free(wolfcrypt_rng);
}

// See the header file for the function documentation
// cppcheck-suppress [misra-c2012-8.7]: API function that can be used in another file.
void LLSEC_RANDOM_IMPL_next_bytes(int32_t native_id, uint8_t *rnd, int32_t size) {
	LLSEC_RANDOM_DEBUG_TRACE("%s(id=%d, size=%d)\n", __func__, native_id, size);
	WC_RNG *wolfcrypt_rng = (WC_RNG *)native_id;
	uint32_t bytes_left = (uint32_t)size;
	uint32_t rnd_index = 0;

	while ((uint32_t)0 < bytes_left) {
		int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
		if ((uint32_t)RNG_MAX_BLOCK_LEN < bytes_left) {
			wolfcrypt_rc = wc_RNG_GenerateBlock(wolfcrypt_rng, &rnd[rnd_index], RNG_MAX_BLOCK_LEN);
			bytes_left -= (uint32_t)RNG_MAX_BLOCK_LEN;
			rnd_index += RNG_MAX_BLOCK_LEN;
		} else {
			wolfcrypt_rc = wc_RNG_GenerateBlock(wolfcrypt_rng, &rnd[rnd_index], bytes_left);
			bytes_left = 0;
		}
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			LLSEC_RANDOM_DEBUG_TRACE("wc_RNG_GenerateBlock() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
#ifdef HAVE_HASHDRBG
			if (RNG_FAILURE_E == wolfcrypt_rc) { // failed to re-seed itself (no entropy source configured?)
				LLSEC_RANDOM_DEBUG_TRACE("Re-seeding...");
				int entropy_size = LLSEC_RANDOM_SEED_SIZE;
				const char *entropy = llsec_gen_random_str_internal(entropy_size);
				if (NULL == entropy) {
					LLSEC_RANDOM_DEBUG_TRACE("llsec_gen_random_str_internal() failed, keep RNG_FAILURE_E error\n");
				} else {
					wolfcrypt_rc = wc_RNG_DRBG_Reseed(wolfcrypt_rng, (byte *)entropy, (word32)entropy_size);
					LLSEC_free((void *)entropy);
					if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
						LLSEC_RANDOM_DEBUG_TRACE("wc_RNG_DRBG_Reseed() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
						(void)SNI_throwNativeException(wolfcrypt_rc, "Could not re-seed random number generator");
						break;
					}
				}
			}
#endif
			(void)SNI_throwNativeException(wolfcrypt_rc, "Could not generate more random bytes");
			break;
		}
	}
}

// See the header file for the function documentation
void LLSEC_RANDOM_IMPL_set_seed(int32_t native_id, uint8_t *seed, int32_t size) {
	LLSEC_RANDOM_DEBUG_TRACE("%s(id=%d, size=%d)\n", __func__, native_id, size);
	WC_RNG *wolfcrypt_rng = (WC_RNG *)native_id;
	int wolfcrypt_rc = wc_RNG_DRBG_Reseed(wolfcrypt_rng, (byte *)seed, (word32)size);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		LLSEC_RANDOM_DEBUG_TRACE("wc_RNG_DRBG_Reseed() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
		(void)SNI_throwNativeException(wolfcrypt_rc, "Could not re-seed random number generator");
	}
}

// See the header file for the function documentation
void LLSEC_RANDOM_IMPL_generate_seed(int32_t native_id, uint8_t *seed, int32_t size) {
	LLSEC_RANDOM_DEBUG_TRACE("%s(id=%d, size=%d)\n", __func__, native_id, size);
	LLSEC_RANDOM_IMPL_next_bytes(native_id, seed, size);
}

// See the header file for the function documentation
int32_t LLSEC_RANDOM_IMPL_get_close_id(void) {
	LLSEC_RANDOM_DEBUG_TRACE("%s\n", __func__);
	return (int32_t)LLSEC_RANDOM_IMPL_close;
}
