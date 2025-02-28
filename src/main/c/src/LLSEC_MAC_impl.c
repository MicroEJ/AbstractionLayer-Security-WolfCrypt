/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - MAC.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_ERRORS.h>
#include <LLSEC_MAC_impl.h>
#include <LLSEC_wolfcrypt.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef struct {
	char *name;
	int type;
	LLSEC_MAC_algorithm_desc description;
} LLSEC_MAC_algorithm;

typedef struct {
	Hmac hmac;
	// Save keys to support the reset ("re-use key") operation
	byte *key;
	word32 key_length;
} LLSEC_MAC;

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static void llsec_mac_close(void *native_id);

/**
 * @brief   Frees the resources and Wolfcrypt context for MAC usage.
 *
 * @param[in]  native_id  Pointer to the Wolfcrypt MAC context structure.
 *
 */
void llsec_mac_close(void *native_id) {
	LLSEC_MAC_DEBUG_TRACE("%s(id=%d)\n", __func__, native_id);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_MAC *mac = (LLSEC_MAC *)native_id;
	wc_HmacFree(&mac->hmac);
	LLSEC_free(mac->key);
	LLSEC_free(mac);
}

// --------------------------------------------------------------------------------
// LLSEC_MAC_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_MAC_IMPL_get_algorithm_description(uint8_t *algorithm_name, LLSEC_MAC_algorithm_desc *algorithm_desc) {
	LLSEC_MAC_DEBUG_TRACE("%s \n", __func__);

	static LLSEC_MAC_algorithm available_mac_algorithms[] = {
#ifndef NO_MD5
		{ .name = "HmacMD5", .type = WC_MD5, { .mac_length = WC_MD5_DIGEST_SIZE } },
#endif // NO_MD5
#ifndef NO_SHA
		{ .name = "HmacSHA1", .type = WC_SHA, { .mac_length = WC_SHA_DIGEST_SIZE } },
#endif // NO_SHA
#ifdef WOLFSSL_SHA224
		{ .name = "HmacSHA224", .type = WC_SHA224, { .mac_length = WC_SHA224_DIGEST_SIZE } },
#endif // WOLFSSL_SHA224
#ifndef NO_SHA256
		{ .name = "HmacSHA256", .type = WC_SHA256, { .mac_length = WC_SHA256_DIGEST_SIZE } },
#endif // NO_SHA256
#ifdef WOLFSSL_SHA384
		{ .name = "HmacSHA384", .type = WC_SHA384, { .mac_length = WC_SHA384_DIGEST_SIZE } },
#endif // WOLFSSL_SHA384
#ifdef WOLFSSL_SHA512
		{ .name = "HmacSHA512", .type = WC_SHA512, { .mac_length = WC_SHA512_DIGEST_SIZE } },
	#ifndef WOLFSSL_NOSHA512_224
		{ .name = "HmacSHA512/224", .type = WC_SHA512_224, { .mac_length = WC_SHA224_DIGEST_SIZE } },
	#endif // WOLFSSL_NOSHA512_224
	#ifndef WOLFSSL_NOSHA512_256
		{ .name = "HmacSHA512/256", .type = WC_SHA512_256, { .mac_length = WC_SHA256_DIGEST_SIZE } },
	#endif // WOLFSSL_NOSHA512_256
#endif // WOLFSSL_SHA512
#ifdef WOLFSSL_SHA3
	#ifndef WOLFSSL_NOSHA3_224
		{ .name = "HmacSHA3-224", .type = WC_SHA3_224, { .mac_length = WC_SHA3_224_DIGEST_SIZE } },
	#endif // WOLFSSL_NOSHA3_224
	#ifndef WOLFSSL_NOSHA3_256
		{ .name = "HmacSHA3-256", .type = WC_SHA3_256, { .mac_length = WC_SHA3_256_DIGEST_SIZE } },
	#endif // WOLFSSL_NOSHA3_256
	#ifndef WOLFSSL_NOSHA3_384
		{ .name = "HmacSHA3-384", .type = WC_SHA3_384, { .mac_length = WC_SHA3_384_DIGEST_SIZE } },
	#endif // WOLFSSL_NOSHA3_384
	#ifndef WOLFSSL_NOSHA3_512
		{ .name = "HmacSHA3-512", .type = WC_SHA3_512, { .mac_length = WC_SHA3_512_DIGEST_SIZE } },
	#endif // WOLFSSL_NOSHA3_512
#endif // WOLFSSL_SHA3
	};

	int32_t return_code = LLSEC_ERROR;
	LLSEC_MAC_algorithm *algorithm = &available_mac_algorithms[0];
	int32_t nb_algorithms = sizeof(available_mac_algorithms) / sizeof(LLSEC_MAC_algorithm);
	while (--nb_algorithms >= 0) {
		if (0 == strcmp((const char *)algorithm_name, algorithm->name)) {
			(void)memcpy(algorithm_desc, &(algorithm->description), sizeof(LLSEC_MAC_algorithm_desc));
			// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
			return_code = (int32_t)algorithm;
			break;
		}
		algorithm++;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_MAC_IMPL_init(int32_t algorithm_id, uint8_t *key, int32_t key_length) {
	LLSEC_MAC_DEBUG_TRACE("%s(alg=%d, len=%d)\n", __func__, algorithm_id, key_length);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_MAC_algorithm *algorithm = (LLSEC_MAC_algorithm *)algorithm_id;
	int32_t return_code = LLSEC_SUCCESS;
	int32_t wolfcrypt_rc;

	LLSEC_MAC *mac = LLSEC_calloc(1, sizeof(LLSEC_MAC));
	if (NULL == mac) {
		(void)SNI_throwNativeException(-1, "Could not allocate MAC buffers");
		return_code = LLSEC_ERROR;
	} else {
		mac->key = (byte *)LLSEC_calloc(1, key_length);
		if (NULL == mac->key) {
			(void)SNI_throwNativeException(-2, "Could not allocate MAC buffers");
			return_code = LLSEC_ERROR;
		} else {
			(void)memcpy(mac->key, key, key_length);
			mac->key_length = key_length;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		wolfcrypt_rc = wc_HmacInit(&mac->hmac, NULL, INVALID_DEVID);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			LLSEC_RANDOM_DEBUG_TRACE("wc_HmacInit() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
			(void)SNI_throwNativeException(wolfcrypt_rc, "Could not initialize HMAC");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		wolfcrypt_rc = wc_HmacSetKey(&mac->hmac, algorithm->type, key, key_length);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			LLSEC_RANDOM_DEBUG_TRACE("wc_HmacSetKey() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
			(void)SNI_throwNativeException(wolfcrypt_rc, "Could not initialize HMAC key");
			return_code = LLSEC_ERROR;
		}
	}

	int32_t native_id;
	if (LLSEC_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		native_id = (int32_t)mac;
		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		if (SNI_OK != SNI_registerResource((void *)native_id, (SNI_closeFunction)llsec_mac_close, NULL)) {
			(void)SNI_throwNativeException(-1, "Could not register SNI native resource");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS != return_code) {
		wc_HmacFree(&mac->hmac);
		LLSEC_free(mac->key);
		LLSEC_free(mac);
	} else {
		return_code = (int32_t)native_id;
	}

	return return_code;
}

// See the header file for the function documentation
void LLSEC_MAC_IMPL_update(int32_t algorithm_id, int32_t native_id, uint8_t *buffer, int32_t buffer_offset,
                           int32_t buffer_length) {
	LLSEC_MAC_DEBUG_TRACE("%s(alg=%d, id=%d, off=%d, len=%d)\n", __func__, algorithm_id, native_id, buffer_offset,
	                      buffer_length);

	LLSEC_UNUSED_PARAM(algorithm_id);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_MAC *mac = (LLSEC_MAC *)native_id;
	int wolfcrypt_rc = wc_HmacUpdate(&mac->hmac, &buffer[buffer_offset], buffer_length);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		LLSEC_RANDOM_DEBUG_TRACE("wc_HmacUpdate() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
		(void)SNI_throwNativeException(wolfcrypt_rc, "HMAC update operation failed");
	}
}

/**
 * @brief Finishes the MAC operation.
 *
 * @param[in] algorithm_id                 The algorithm ID.
 * @param[in] native_id                    The native ID.
 * @param[out] out                         The MAC result.
 * @param[in] out_offset                   The offset of the out buffer.
 * @param[in] out_length                   The length of the out buffer.
 *
 * @note Throws NativeException on error.
 *
 * @warning <code>out</code> must not be used outside of the VM task or saved.
 */
void LLSEC_MAC_IMPL_do_final(int32_t algorithm_id, int32_t native_id, uint8_t *out, int32_t out_offset,
                             int32_t out_length) {
	LLSEC_MAC_DEBUG_TRACE("%s(alg=%d, id=%d, off=%d, len=%d)\n", __func__, algorithm_id, native_id, out_offset,
	                      out_length);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_MAC_algorithm *algorithm = (LLSEC_MAC_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_MAC *mac = (LLSEC_MAC *)native_id;
	if (((uint32_t)out_length) < algorithm->description.mac_length) {
		(void)SNI_throwNativeException(-1, "Internal error: buffer too small");
	} else {
		int wolfcrypt_rc = wc_HmacFinal(&mac->hmac, &out[out_offset]);
		if (LLSEC_SUCCESS != wolfcrypt_rc) {
			LLSEC_RANDOM_DEBUG_TRACE("wc_HmacFinal() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
			(void)SNI_throwNativeException(wolfcrypt_rc, "HMAC final operation failed");
		}
	}
}

/**
 * @brief Resets the MAC resource.
 *
 * @param[in] algorithm_id                 The algorithm ID.
 * @param[in] native_id                    The native ID.
 *
 * @note Throws NativeException on error.
 */
void LLSEC_MAC_IMPL_reset(int32_t algorithm_id, int32_t native_id) {
	LLSEC_MAC_DEBUG_TRACE("%s(alg=%d, id=%d)\n", __func__, algorithm_id, native_id);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_MAC_algorithm *algorithm = (LLSEC_MAC_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_MAC *mac = (LLSEC_MAC *)native_id;
	int wolfcrypt_rc = wc_HmacSetKey(&mac->hmac, algorithm->type, mac->key, mac->key_length);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		LLSEC_RANDOM_DEBUG_TRACE("wc_HmacSetKey() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
		(void)SNI_throwNativeException(wolfcrypt_rc, "LLSEC_MAC_IMPL_reset failed");
	}
}

/**
 * @brief Closes the resources related to the native id.
 *
 * @param[in] algorithm_id                 The algorithm ID.
 * @param[in] native_id                    The native ID.
 *
 * @note Throws NativeException on error.
 */
void LLSEC_MAC_IMPL_close(int32_t algorithm_id, int32_t native_id) {
	LLSEC_MAC_DEBUG_TRACE("%s(alg=%d, id=%d)\n", __func__, algorithm_id, native_id);
	LLSEC_UNUSED_PARAM(algorithm_id);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_MAC *mac = (LLSEC_MAC *)native_id;
	wc_HmacFree(&mac->hmac);
	LLSEC_free(mac->key);
	LLSEC_free(mac);
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	if (SNI_OK != SNI_unregisterResource((void *)native_id, (SNI_closeFunction)llsec_mac_close)) {
		(void)SNI_throwNativeException(-1, "Could not unregister SNI native resource\n");
	}
}

/**
 * @brief Gets the id of the native close function.
 *
 * @param[in] algorithm_id                 The algorithm ID.
 *
 * @return the id of the static native close function.
 *
 * @note Throws NativeException on error.
 */
int32_t LLSEC_MAC_IMPL_get_close_id(int32_t algorithm_id) {
	LLSEC_MAC_DEBUG_TRACE("%s(alg=%d)\n", __func__, algorithm_id);
	LLSEC_UNUSED_PARAM(algorithm_id);
	return (int32_t)llsec_mac_close;
}
