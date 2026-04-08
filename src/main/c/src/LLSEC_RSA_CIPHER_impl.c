/*
 * C
 *
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief MicroEJ Security low level API implementation for Wolfcrypt Library.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_common.h>
#include <LLSEC_RSA_CIPHER_impl.h>
#include <LLSEC_ERRORS.h>
#include <LLSEC_wolfcrypt.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef int32_t (*LLSEC_RSA_CIPHER_init)(int32_t transformation_id, void **native_id, uint8_t is_decrypting,
                                         int32_t key_id, int32_t padding, int32_t hash);
typedef int32_t (*LLSEC_RSA_CIPHER_decrypt)(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output);
typedef int32_t (*LLSEC_RSA_CIPHER_encrypt)(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output);
typedef void (*LLSEC_RSA_CIPHER_close)(void *native_id);

typedef struct {
	char *name; // the name of the transformation
	LLSEC_RSA_CIPHER_init init;
	LLSEC_RSA_CIPHER_decrypt decrypt;
	LLSEC_RSA_CIPHER_encrypt encrypt;
	LLSEC_RSA_CIPHER_close close;
	LLSEC_RSA_CIPHER_transformation_desc description;
} LLSEC_RSA_CIPHER_transformation;

typedef struct {
	LLSEC_RSA_CIPHER_transformation *transformation;
	RsaKey *rsa_ctx;
	WC_RNG *rng_ctx;
} LLSEC_RSA_CIPHER_ctx;

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static int32_t llsec_rsa_cipher_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                     int32_t padding_type, int32_t oaep_hash_algorithm);
static int32_t llsec_rsa_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output);
static int32_t llsec_rsa_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output);
static void llsec_rsa_cipher_close(void *native_id);

/**
 * @brief   Creates and initializes a Wolfcrypt to manipulate RSA ciphers.
 *
 * @param[in]  transformation_id  Pointer to the transformation description
 * @param[out]  native_id   Pointer pointer to the RSA key native structure created.
 * @param[in]   is_decrypting  '1' for decrypting, '0' for encryting.
 * @param[in]   key_id  Reference to the native key structure
 * @param[in]   padding_type The RSA padding type.
 * @param[in] oaep_hash_algorithm        The hash algorithm for OAEP RSA padding type.
 *
 * @return     LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t llsec_rsa_cipher_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                     int32_t padding_type, int32_t oaep_hash_algorithm) {
	LLSEC_UNUSED_PARAM(oaep_hash_algorithm);
	LLSEC_UNUSED_PARAM(padding_type);
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	RsaKey *key_ctx = NULL;
	LLSEC_RSA_CIPHER_ctx *cipher_ctx;
	LLSEC_RSA_CIPHER_DEBUG_TRACE("%s\n", __func__);
	WOLFSSL_HEAP_HINT *pHint = llsec_wolfssl_get_heap();

	cipher_ctx = (LLSEC_RSA_CIPHER_ctx *)llsec_calloc(1, (int32_t)sizeof(LLSEC_RSA_CIPHER_ctx));
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	cipher_ctx->transformation = (LLSEC_RSA_CIPHER_transformation *)transformation_id;

	if ((uint8_t)0 != is_decrypting) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLSEC_priv_key *key = (LLSEC_priv_key *)key_id;
		key_ctx = (RsaKey *)key->any_key;
	} else {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLSEC_pub_key *key = (LLSEC_pub_key *)key_id;
		key_ctx = (RsaKey *)key->any_key;
	}

	cipher_ctx->rsa_ctx = key_ctx;

	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		llsec_throw(wolfcrypt_rc, "wc_InitRsaKey failed");
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		WC_RNG *wolfcrypt_rng;
		char *pers = llsec_gen_random_str_internal(8);
		wolfcrypt_rng = wc_rng_new((byte *)pers, (word32)strlen(pers), pHint);

		if (NULL == wolfcrypt_rng) {
			llsec_throw(wolfcrypt_rc, "Failed to initialize random number generator for RSA Cipher");
			wc_rng_free(wolfcrypt_rng);

			llsec_free((void *)pers);
			return_code = LLSEC_ERROR;
		} else {
			wolfcrypt_rc = wc_InitRng_ex(wolfcrypt_rng, pHint, INVALID_DEVID);
			wolfcrypt_rc += wc_RsaSetRNG(cipher_ctx->rsa_ctx, wolfcrypt_rng);
			cipher_ctx->rng_ctx = wolfcrypt_rng;
			if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
				llsec_throw(wolfcrypt_rc, "Failed to set random number generator for RSA");
				return_code = LLSEC_ERROR;
			}
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		*native_id = cipher_ctx;
	}
	return return_code;
}

/**
 * @brief   Decryptes a data buffer using a provided Wolfcrypt native context with RSA keys.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt RSA key structure.
 * @param[in]  buffer  Pointer to the encrypted data buffer.
 * @param[in]  buffer_length  Size of the encrypted data buffer.
 * @param[in]  output  Pointer to a buffer to store decrypted data.
 *
 * @return     Number of decrypted bytes, or LLSEC_ERROR if an error occures.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t llsec_rsa_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output) {
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_ctx *cipher_ctx = (LLSEC_RSA_CIPHER_ctx *)native_id;
	LLSEC_RSA_CIPHER_DEBUG_TRACE("%s\n", __func__);

	int32_t return_code = LLSEC_SUCCESS;

	int wolfcrypt_rc = wc_RsaPrivateDecrypt_ex(buffer,
	                                           buffer_length, output,
	                                           // cppcheck-suppress [misra-c2012-11.3] : From sni.h with
	                                           // SNI_getArrayLength, cast used by many C framework to
	                                           // factorize code.
	                                           // cppcheck-suppress [misra-c2012-18.4] : From sni.h with
	                                           // SNI_getArrayLength, used for configurable C library.
	                                           SNI_getArrayLength(output),
	                                           cipher_ctx->rsa_ctx,
	                                           llsec_rsa_get_padding(
												   cipher_ctx->transformation->description.padding_type),
	                                           llsec_rsa_get_wc_hash(
												   cipher_ctx->transformation->description.oaep_hash_algorithm),
	                                           wc_hash2mgf(llsec_rsa_get_wc_hash(
															   cipher_ctx->transformation->description.
															   oaep_hash_algorithm)),
	                                           NULL, 0);

	if (LLSEC_WOLFCRYPT_SUCCESS <= wolfcrypt_rc) {
		return_code = wolfcrypt_rc;
	} else {
		llsec_throw(wolfcrypt_rc, "llsec_rsa_cipher_decrypt failed");
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

/**
 * @brief   Encryptes a data buffer using a provided Wolfcrypt native context with RSA keys.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt RSA key structure.
 * @param[in]  buffer  Pointer to the data buffer to encrypt.
 * @param[in]  buffer_length  Size of the data buffer.
 * @param[in]  output  Pointer to a buffer to store encrypted data.
 *
 * @return     Number of encrypted bytes, or LLSEC_ERROR if an error occures.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t llsec_rsa_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output) {
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_ctx *cipher_ctx = (LLSEC_RSA_CIPHER_ctx *)native_id;
	LLSEC_RSA_CIPHER_DEBUG_TRACE("%s\n", __func__);

	int32_t return_code = LLSEC_SUCCESS;

	// cppcheck-suppress [misra-c2012-11.3] : From sni.h with SNI_getArrayLength, cast used by many C framework to
	// factorize code.
	// cppcheck-suppress [misra-c2012-18.4] : From sni.h with SNI_getArrayLength, used for configurable C library.
	int wolfcrypt_rc = wc_RsaPublicEncrypt_ex(buffer, buffer_length, output, SNI_getArrayLength(output),
	                                          cipher_ctx->rsa_ctx, cipher_ctx->rng_ctx,
	                                          llsec_rsa_get_padding(
												  cipher_ctx->transformation->description.padding_type),
	                                          llsec_rsa_get_wc_hash(
												  cipher_ctx->transformation->description.oaep_hash_algorithm),
	                                          wc_hash2mgf(llsec_rsa_get_wc_hash(
															  cipher_ctx->transformation->description.
															  oaep_hash_algorithm)),
	                                          NULL, 0);

	if (LLSEC_WOLFCRYPT_SUCCESS <= wolfcrypt_rc) {
		return_code = wolfcrypt_rc;
	} else {
		llsec_throw(wolfcrypt_rc, "llsec_rsa_cipher_encrypt failed");
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

/**
 * @brief   Frees the resources and context associated of an Wolfcrypt RSA key structure.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt RSA key structure.
 *
 */
static void llsec_rsa_cipher_close(void *native_id) {
	LLSEC_RSA_CIPHER_DEBUG_TRACE("%s native_id:%p\n", __func__, native_id);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_ctx *cipher_ctx = (LLSEC_RSA_CIPHER_ctx *)native_id;
	wc_FreeRng(cipher_ctx->rng_ctx);
	llsec_free(native_id);
}

// --------------------------------------------------------------------------------
// LLSEC_RSA_CIPHER_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_RSA_CIPHER_IMPL_get_transformation_description(uint8_t *transformation_name,
                                                             LLSEC_RSA_CIPHER_transformation_desc *transformation_desc)
{
	int32_t return_code = LLSEC_ERROR;
	LLSEC_RSA_CIPHER_DEBUG_TRACE("%s transformation_name %s\n", __func__, transformation_name);

	static LLSEC_RSA_CIPHER_transformation available_transformations[] = {
#if defined(NO_RSA)
		{
			.name = "",
			.init = NULL,
			.decrypt = NULL,
			.encrypt = NULL,
			.close = NULL,
			.description = {
				.padding_type = 0,
				.oaep_hash_algorithm = 0,
			},
		}
#else
		{
			.name = "RSA/ECB/PKCS1Padding",
			.init = llsec_rsa_cipher_init,
			.decrypt = llsec_rsa_cipher_decrypt,
			.encrypt = llsec_rsa_cipher_encrypt,
			.close = llsec_rsa_cipher_close,
			{
				.padding_type = PAD_PKCS1_TYPE,
				.oaep_hash_algorithm = OAEP_HASH_SHA_1_ALGORITHM,
			},
		},
		{
			.name = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
			.init = llsec_rsa_cipher_init,
			.decrypt = llsec_rsa_cipher_decrypt,
			.encrypt = llsec_rsa_cipher_encrypt,
			.close = llsec_rsa_cipher_close,
			{
				.padding_type = PAD_OAEP_MGF1_TYPE,
				.oaep_hash_algorithm = OAEP_HASH_SHA_1_ALGORITHM,
			},
		},
		{
			.name = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
			.init = llsec_rsa_cipher_init,
			.decrypt = llsec_rsa_cipher_decrypt,
			.encrypt = llsec_rsa_cipher_encrypt,
			.close = llsec_rsa_cipher_close,
			{
				.padding_type = PAD_OAEP_MGF1_TYPE,
				.oaep_hash_algorithm = OAEP_HASH_SHA_256_ALGORITHM,
			},
		},
#endif // NO_RSA
	};

	int32_t nb_transformations = sizeof(available_transformations) / sizeof(LLSEC_RSA_CIPHER_transformation);
	LLSEC_RSA_CIPHER_transformation *transformation = &available_transformations[0];

	while (--nb_transformations >= 0) {
		if (0 == strcmp((const char *)transformation_name, transformation->name)) {
			transformation_desc->padding_type = transformation->description.padding_type;
			transformation_desc->oaep_hash_algorithm = transformation->description.oaep_hash_algorithm;
			break;
		}
		transformation++;
	}

	if (0 <= nb_transformations) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		return_code = (int32_t)transformation;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_RSA_CIPHER_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, int32_t key_id,
                                   int32_t padding_type, int32_t oaep_hash_algorithm) {
	int32_t return_code = LLSEC_SUCCESS;
	LLSEC_RSA_CIPHER_DEBUG_TRACE("%s\n", __func__);
	void *native_id = NULL;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_transformation *transformation = (LLSEC_RSA_CIPHER_transformation *)transformation_id;

	if (0 == key_id) {
		llsec_throw(key_id, "LLSEC_RSA_CIPHER_IMPL_init invalid key_id");
		return_code = LLSEC_ERROR;
	}

	if ((PAD_PKCS1_TYPE != (uint32_t)padding_type) && (PAD_OAEP_MGF1_TYPE != (uint32_t)padding_type)) {
		llsec_throw(padding_type, "LLSEC_RSA_CIPHER_IMPL_init invalid padding_type");
		return_code = LLSEC_ERROR;
	}

	if ((PAD_OAEP_MGF1_TYPE == (uint32_t)padding_type) &&
	    (OAEP_HASH_SHA_1_ALGORITHM != (uint32_t)oaep_hash_algorithm) &&
	    (OAEP_HASH_SHA_256_ALGORITHM != (uint32_t)oaep_hash_algorithm)) {
		llsec_throw(oaep_hash_algorithm, "LLSEC_RSA_CIPHER_IMPL_init invalid oaep_hash_algorithm");
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		return_code = transformation->init(transformation_id, (void **)&native_id, is_decrypting, key_id, padding_type,
		                                   oaep_hash_algorithm);

		if (LLSEC_SUCCESS != return_code) {
			llsec_throw(return_code, "LLSEC_RSA_CIPHER_IMPL_init failed");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_OK != SNI_registerResource(native_id, transformation->close, NULL)) {
			llsec_throw(LLSEC_ERROR, "Can't register SNI native resource");
			transformation->close((void *)native_id);
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		return_code = (int32_t)(native_id);
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_RSA_CIPHER_IMPL_decrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                      int32_t buffer_offset, int32_t buffer_length, uint8_t *output,
                                      int32_t output_offset) {
	LLSEC_RSA_CIPHER_DEBUG_TRACE("%s\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_transformation *transformation = (LLSEC_RSA_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	int32_t return_code = transformation->decrypt((void *)native_id, &buffer[buffer_offset], buffer_length,
	                                              &output[output_offset]);
	if (0 > return_code) {
		llsec_throw(return_code, "LLSEC_RSA_CIPHER_IMPL_decrypt failed");
		return_code = LLSEC_ERROR;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_RSA_CIPHER_IMPL_encrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                      int32_t buffer_offset, int32_t buffer_length, uint8_t *output,
                                      int32_t output_offset) {
	LLSEC_RSA_CIPHER_DEBUG_TRACE("%s\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_transformation *transformation = (LLSEC_RSA_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	int32_t return_code = transformation->encrypt((void *)native_id, &buffer[buffer_offset], buffer_length,
	                                              &output[output_offset]);
	if (0 > return_code) {
		llsec_throw(return_code, "LLSEC_RSA_CIPHER_IMPL_encrypt failed");
		return_code = LLSEC_ERROR;
	}
	return return_code;
}

// See the header file for the function documentation
void LLSEC_RSA_CIPHER_IMPL_close(int32_t transformation_id, int32_t native_id) {
	LLSEC_RSA_CIPHER_DEBUG_TRACE("%s\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_transformation *transformation = (LLSEC_RSA_CIPHER_transformation *)transformation_id;

	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	transformation->close((void *)native_id);
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	if (SNI_OK != SNI_unregisterResource((void *)native_id, (SNI_closeFunction)transformation->close)) {
		llsec_throw(LLSEC_ERROR, "Can't unregister SNI native resource");
	}
}

// See the header file for the function documentation
int32_t LLSEC_RSA_CIPHER_IMPL_get_close_id(int32_t transformation_id) {
	LLSEC_RSA_CIPHER_DEBUG_TRACE("%s\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_RSA_CIPHER_transformation *transformation = (LLSEC_RSA_CIPHER_transformation *)transformation_id;

	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)transformation->close;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
