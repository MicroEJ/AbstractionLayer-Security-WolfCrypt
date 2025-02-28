/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Public key PKCS8 encoding.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_ERRORS.h>
#include <LLSEC_PUBLIC_KEY_impl.h>
#include <LLSEC_wolfcrypt.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------------
// Variable declarations
// --------------------------------------------------------------------------------

/**
 * @brief Public pk context.
 * Received as input by the LLSEC_PUBLIC native functions, contains an initialized public key context
 * that will be used by the public pk context.
 */
static void *pub_pk_ctx;

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static void *pub_ctx_alloc_func(void) {
	return pub_pk_ctx;
}

static void pub_ctx_free_func(void *ctx) {
	// nothing to do, context is received as input to the native function, so it must not be freed here
	LLSEC_UNUSED_PARAM(ctx);
}

// --------------------------------------------------------------------------------
// LLSEC_PUBLIC_KEY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_PUBLIC_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLSEC_PUBLIC_KEY_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_pub_key *key = (LLSEC_pub_key *)native_id;

	int return_code = LLSEC_ERROR;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	pub_pk_ctx = (void *)key->key;

	if (TYPE_RSA == key->key_type) {
		wolfcrypt_rc = wc_RsaPublicKeyDerSize((RsaKey *)pub_pk_ctx, 1);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "Encoded key max size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
	} else {
		// need to implement ECDSA
		wolfcrypt_rc = wc_EccPublicKeyDerSize((ecc_key *)pub_pk_ctx, 1);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "Encoded key max size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_PUBLIC_KEY_IMPL_get_encode(int32_t native_id, uint8_t *output, int32_t outputLength) {
	LLSEC_PUBLIC_KEY_DEBUG_TRACE("%s \n", __func__);
	int return_code = LLSEC_ERROR;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_pub_key *key = (LLSEC_pub_key *)native_id;
	pub_pk_ctx = (void *)key->key;

	if (TYPE_RSA == key->key_type) {
		wolfcrypt_rc = wc_RsaKeyToPublicDer((RsaKey *)pub_pk_ctx, output, outputLength);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "Public key encoding failed");
		} else {
			return_code = wolfcrypt_rc;
		}
	} else {
		// ECDSA key type
		wolfcrypt_rc = wc_EccPublicKeyToDer((ecc_key *)pub_pk_ctx, output, outputLength, 1);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "Public key encoding failed");
		} else {
			return_code = wolfcrypt_rc;
		}
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_PUBLIC_KEY_IMPL_get_output_size(int32_t native_id) {
	LLSEC_PUBLIC_KEY_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_pub_key *key = (LLSEC_pub_key *)native_id;

	int return_code = LLSEC_ERROR;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	pub_pk_ctx = (void *)key->key;

	if (TYPE_RSA == key->key_type) {
		wolfcrypt_rc = wc_RsaEncryptSize((RsaKey *)pub_pk_ctx);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "Output buffer size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
	} else {
		// ECDSA key type
		wolfcrypt_rc = wc_ecc_size((ecc_key *)pub_pk_ctx);
		if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "Output buffer size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
	}
	return return_code;
}
