/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Cipher (encryption/decryption).
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_CIPHER_impl.h>
#include <LLSEC_ERRORS.h>
#include <LLSEC_wolfcrypt.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------------
// Macros and Defines
// --------------------------------------------------------------------------------

#define AES_CBC_BLOCK_BITS    (128u)
#define AES_CBC_BLOCK_BYTES   (AES_CBC_BLOCK_BITS / 8u)
#define AES_CBC_IV_SIZE       AES_BLOCK_SIZE

#define DES_CBC_BLOCK_BITS    (64u)
#define DES_CBC_BLOCK_BYTES   (DES_CBC_BLOCK_BITS / 8u)
#define DES_CBC_IV_SIZE       DES_BLOCK_SIZE

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef int (*LLSEC_CIPHER_init)(int32_t transformation_id, void **native_id, uint8_t is_decrypting, uint8_t *key,
                                 int32_t key_length, uint8_t *iv, int32_t iv_length);
typedef int (*LLSEC_CIPHER_decrypt)(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output);
typedef int (*LLSEC_CIPHER_encrypt)(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output);
typedef void (*LLSEC_CIPHER_set_iv)(void *native_id, uint8_t *iv, int32_t iv_length);
typedef void (*LLSEC_CIPHER_close)(void *native_id);

typedef struct {
	char *name; // the name of the transformation
	LLSEC_CIPHER_init init;
	LLSEC_CIPHER_decrypt decrypt;
	LLSEC_CIPHER_encrypt encrypt;
	LLSEC_CIPHER_close close;
	LLSEC_CIPHER_set_iv set_iv;
	LLSEC_CIPHER_transformation_desc description;
} LLSEC_CIPHER_transformation;

// cppcheck-suppress [misra-c2012-19.2]: Generic justification, is useful when designing C library.
typedef union {
	Aes aes_ctx;
	Des3 des3_ctx;
} cipher_ctx;

typedef struct {
	LLSEC_CIPHER_transformation *transformation;
	// cppcheck-suppress [misra-c2012-19.2]: Generic justification, is useful when designing C library.
	cipher_ctx wolfcrypt_ctx;
	int32_t iv_length;
	uint8_t iv[1];
} LLSEC_CIPHER_ctx;

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static int LLSEC_CIPHER_aescbc_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, uint8_t *key,
                                    int32_t key_length, uint8_t *iv, int32_t iv_length);
static int LLSEC_CIPHER_des3cbc_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, uint8_t *key,
                                     int32_t key_length, uint8_t *iv, int32_t iv_length);
static int wolfcrypt_aes_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output);
static int wolfcrypt_des3_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output);
static int wolfcrypt_aes_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output);
static int wolfcrypt_des3_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output);
static void wolfcrypt_aes_cipher_set_iv(void *native_id, uint8_t *iv, int32_t iv_length);
static void wolfcrypt_des3_cipher_set_iv(void *native_id, uint8_t *iv, int32_t iv_length);
static void wolfcrypt_aes_cipher_close(void *native_id);
static void wolfcrypt_des3_cipher_close(void *native_id);

/**
 * @brief  Creates and initializes the Wolfcrypt native structure to use AES ciphers.
 *
 * @param[in]  transformation_id  Pointer to the transformation description
 * @param[out]  native_id   Pointer pointer to the AES native structure.
 * @param[in]   is_decrypting  Cipher direction : '1' for decrypting, '0' for encryting.
 * @param[in]   key  Pointer to a buffer containing the key for the AES cipher.
 * @param[in]   key_length Size of the AES key (in bytes).
 * @param[in]   iv Pointer to the initialization vector used to initialize the key
 * @param[in]   iv_length Size of the initialization vector (in bytes)
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int LLSEC_CIPHER_aescbc_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, uint8_t *key,
                                    int32_t key_length, uint8_t *iv, int32_t iv_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s %d\n", __func__, is_decrypting);

	LLSEC_CIPHER_ctx *cipher_ctx;
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	//
	cipher_ctx = (LLSEC_CIPHER_ctx *)LLSEC_calloc(1, (int32_t)sizeof(LLSEC_CIPHER_ctx) - 1 + AES_CBC_IV_SIZE);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	cipher_ctx->transformation = (LLSEC_CIPHER_transformation *)transformation_id;

	if (AES_CBC_IV_SIZE < iv_length) {
		cipher_ctx->iv_length = AES_CBC_IV_SIZE;
	} else {
		cipher_ctx->iv_length = iv_length;
	}

	(void)memcpy(cipher_ctx->iv, iv, cipher_ctx->iv_length);

	//
	wc_AesInit(&cipher_ctx->wolfcrypt_ctx.aes_ctx, NULL, INVALID_DEVID);

	//
	if ((uint8_t)0 != is_decrypting) {
		wolfcrypt_rc = wc_AesSetKey(&cipher_ctx->wolfcrypt_ctx.aes_ctx, key, key_length, iv, AES_DECRYPTION);
		LLSEC_CIPHER_DEBUG_TRACE("%s wolfcrypt_aes_setkey_dec (rc = %d)\n", __func__, wolfcrypt_rc);
	} else {
		wolfcrypt_rc = wc_AesSetKey(&cipher_ctx->wolfcrypt_ctx.aes_ctx, key, key_length, iv, AES_ENCRYPTION);
		LLSEC_CIPHER_DEBUG_TRACE("%s wolfcrypt_aes_setkey_enc (rc = %d)\n", __func__, wolfcrypt_rc);
	}

	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		cipher_ctx->iv_length = iv_length;
		(void)memcpy(cipher_ctx->iv, iv, iv_length);
		*native_id = cipher_ctx;
	} else {
		wc_AesFree(&cipher_ctx->wolfcrypt_ctx.aes_ctx);
		LLSEC_free(cipher_ctx);
	}
	return return_code;
}

/**
 * @brief  Creates and initializes the Wolfcrypt native structure to use DES ciphers.
 *
 * @param[in]  transformation_id  Pointer to the transformation description
 * @param[out]  native_id   Pointer pointer to the DES native structure.
 * @param[in]   is_decrypting  Cipher direction : '1' for decrypting, '0' for encryting.
 * @param[in]   key  Pointer to a buffer containing the key for the DES cipher.
 * @param[in]   key_length Size of the DES key (in bytes).
 * @param[in]   iv Pointer to the initialization vector used to initialize the key
 * @param[in]   iv_length Size of the initialization vector (in bytes)
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int LLSEC_CIPHER_des3cbc_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, uint8_t *key,
                                     int32_t key_length, uint8_t *iv, int32_t iv_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s %d\n", __func__, is_decrypting);

	LLSEC_UNUSED_PARAM(key_length);

	LLSEC_CIPHER_ctx *cipher_ctx;
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;

	cipher_ctx = LLSEC_calloc(1, (int32_t)sizeof(LLSEC_CIPHER_ctx) - 1 + DES_CBC_IV_SIZE);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	cipher_ctx->transformation = (LLSEC_CIPHER_transformation *)transformation_id;

	if (DES_CBC_IV_SIZE < iv_length) {
		cipher_ctx->iv_length = DES_CBC_IV_SIZE;
	} else {
		cipher_ctx->iv_length = iv_length;
	}

	(void)memcpy(cipher_ctx->iv, iv, cipher_ctx->iv_length);

	wc_Des3Init(&cipher_ctx->wolfcrypt_ctx.des3_ctx, NULL, INVALID_DEVID);

	if ((uint8_t)0 != is_decrypting) {
		wolfcrypt_rc = wc_Des3_SetKey(&cipher_ctx->wolfcrypt_ctx.des3_ctx, key, iv, DES_DECRYPTION);
		LLSEC_CIPHER_DEBUG_TRACE("%s mbedtls_des3_set3key_dec (rc = %d)\n", __func__, wolfcrypt_rc);
	} else {
		wolfcrypt_rc = wc_Des3_SetKey(&cipher_ctx->wolfcrypt_ctx.des3_ctx, key, iv, DES_ENCRYPTION);
		LLSEC_CIPHER_DEBUG_TRACE("%s mbedtls_des3_set3key_enc (rc = %d)\n", __func__, wolfcrypt_rc);
	}

	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		cipher_ctx->iv_length = iv_length;
		(void)memcpy(cipher_ctx->iv, iv, iv_length);
		*native_id = cipher_ctx;
	} else {
		wc_Des3Free(&cipher_ctx->wolfcrypt_ctx.des3_ctx);
		LLSEC_free(cipher_ctx);
	}
	return return_code;
}

/**
 * @brief Decryptes a data buffer with AES  and stores them in an output buffer.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt AES native structure.
 * @param[in]  buffer Pointer to the data buffer to decrypt.
 * @param[in]  buffer_length Size of the data to decrypt (in bytes).
 * @param[in]  output Pointer to the buffer to store decrypted bytes.
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int wolfcrypt_aes_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);

	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_AesCbcDecrypt(&cipher_ctx->wolfcrypt_ctx.aes_ctx, output, buffer, buffer_length);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

/**
 * @brief Decryptes a data buffer with DES  and stores them in an output buffer.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt DES native structure.
 * @param[in]  buffer Pointer to the data buffer to decrypt.
 * @param[in]  buffer_length Size of the data to decrypt (in bytes).
 * @param[in]  output Pointer to the buffer to store decrypted bytes.
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int wolfcrypt_des3_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);

	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_Des3_CbcDecrypt(&cipher_ctx->wolfcrypt_ctx.des3_ctx, output, buffer, buffer_length);

	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}
	return return_code;
}

/**
 * @brief Encryptes a data buffer with AES and stores them in an output buffer.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt AES native structure.
 * @param[in]  buffer Pointer to the data buffer to encrypt.
 * @param[in]  buffer_length Size of the data to encrypt (in bytes).
 * @param[in]  output Pointer to the buffer to store encrypted bytes.
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int wolfcrypt_aes_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_AesCbcEncrypt(&cipher_ctx->wolfcrypt_ctx.aes_ctx, output, buffer, buffer_length);

	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

/**
 * @brief Encryptes a data buffer with DES and stores them in an output buffer.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt DES native structure.
 * @param[in]  buffer Pointer to the data buffer to encrypt.
 * @param[in]  buffer_length Size of the data to encrypt (in bytes).
 * @param[in]  output Pointer to the buffer to store encrypted bytes.
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int wolfcrypt_des3_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_Des3_CbcEncrypt(&cipher_ctx->wolfcrypt_ctx.des3_ctx, output, buffer, buffer_length);

	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

/**
 * @brief Set the initialization vector of an Wolfcrypt AES key.
 *
 * @param[in]  native_id Pointer to Wolfcrypt AES key native structure.
 * @param[in]  iv Pointer to the buffer containing the initialization vector.
 * @param[in]  iv_length Size of the initialization vector (in bytes).
 *
 */
static void wolfcrypt_aes_cipher_set_iv(void *native_id, uint8_t *iv, int32_t iv_length) {
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	if (AES_CBC_IV_SIZE < iv_length) {
		cipher_ctx->iv_length = AES_CBC_IV_SIZE;
	} else {
		cipher_ctx->iv_length = iv_length;
	}

	(void)memcpy(cipher_ctx->iv, iv, cipher_ctx->iv_length);
	wc_AesSetIV(&cipher_ctx->wolfcrypt_ctx.aes_ctx, cipher_ctx->iv);
}

/**
 * @brief Set the initialization vector of an Wolfcrypt DES key.
 *
 * @param[in]  native_id Pointer to Wolfcrypt AES key native structure.
 * @param[in]  iv Pointer to the buffer containing the initialization vector.
 * @param[in]  iv_length Size of the initialization vector (in bytes).
 *
 */
static void wolfcrypt_des3_cipher_set_iv(void *native_id, uint8_t *iv, int32_t iv_length) {
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;
	cipher_ctx->iv_length = iv_length;
	(void)memcpy(cipher_ctx->iv, iv, cipher_ctx->iv_length);
	wc_Des3_SetIV(&cipher_ctx->wolfcrypt_ctx.des3_ctx, cipher_ctx->iv);
}

/**
 * @brief Frees the resources and context associated of an Wolfcrypt AES key structure.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt AES key structure.
 *
 */
static void wolfcrypt_aes_cipher_close(void *native_id) {
	LLSEC_CIPHER_DEBUG_TRACE("%s native_id %p\n", __func__, native_id);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;
	wc_AesFree(&cipher_ctx->wolfcrypt_ctx.aes_ctx);
	LLSEC_free(native_id);
}

/**
 * @brief Frees the resources and context associated of an Wolfcrypt DES key structure.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt DES key structure.
 *
 */
static void wolfcrypt_des3_cipher_close(void *native_id) {
	LLSEC_CIPHER_DEBUG_TRACE("%s native_id %p\n", __func__, native_id);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;
	wc_Des3Free(&cipher_ctx->wolfcrypt_ctx.des3_ctx);
	LLSEC_free(native_id);
}

// --------------------------------------------------------------------------------
// LLSEC_CIPHER_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_get_transformation_description(uint8_t *transformation_name,
                                                         LLSEC_CIPHER_transformation_desc *transformation_desc) {
	LLSEC_CIPHER_DEBUG_TRACE("%s transformation_name %s\n", __func__, transformation_name);

	static LLSEC_CIPHER_transformation available_transformations[2] = {
		{
			.name = "AES/CBC/NoPadding",
			.init = LLSEC_CIPHER_aescbc_init,
			.decrypt = wolfcrypt_aes_cipher_decrypt,
			.encrypt = wolfcrypt_aes_cipher_encrypt,
			.close = wolfcrypt_aes_cipher_close,
			.set_iv = wolfcrypt_aes_cipher_set_iv,
			{
				.block_size = AES_CBC_BLOCK_BYTES,
				.unit_bytes = AES_CBC_BLOCK_BYTES,
				.cipher_mode = CBC_MODE,
			},
		},
		{
			.name = "DESede/CBC/NoPadding",
			.init = LLSEC_CIPHER_des3cbc_init,
			.decrypt = wolfcrypt_des3_cipher_decrypt,
			.encrypt = wolfcrypt_des3_cipher_encrypt,
			.close = wolfcrypt_des3_cipher_close,
			.set_iv = wolfcrypt_des3_cipher_set_iv,
			{
				.block_size = DES_CBC_BLOCK_BYTES,
				.unit_bytes = DES_CBC_BLOCK_BYTES,
				.cipher_mode = CBC_MODE,
			},
		}
	};

	int32_t return_code = LLSEC_SUCCESS;
	int32_t nb_transformations = sizeof(available_transformations) / sizeof(LLSEC_CIPHER_transformation);
	LLSEC_CIPHER_transformation *transformation = &available_transformations[0];

	while (--nb_transformations >= 0) {
		if (strcmp((const char *)transformation_name, transformation->name) == 0) {
			(void)memcpy(transformation_desc, &(transformation->description), sizeof(LLSEC_CIPHER_transformation_desc));
			break;
		}
		transformation++;
	}

	if (nb_transformations >= 0) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		return_code = (int32_t)transformation;
	} else {
		return_code = LLSEC_ERROR;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_get_buffered_length(int32_t nativeTransformationId, int32_t nativeId) {
	LLSEC_UNUSED_PARAM(nativeTransformationId);
	LLSEC_UNUSED_PARAM(nativeId);
	return LLSEC_SUCCESS;
}

// See the header file for the function documentation
void LLSEC_CIPHER_IMPL_get_IV(int32_t transformation_id, int32_t native_id, uint8_t *iv, int32_t iv_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	LLSEC_UNUSED_PARAM(transformation_id);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;
	(void)memcpy(iv, cipher_ctx->iv, iv_length);
}

// See the header file for the function documentation
void LLSEC_CIPHER_IMPL_set_IV(int32_t transformation_id, int32_t native_id, uint8_t *iv, int32_t iv_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	transformation->set_iv((void *)native_id, iv, iv_length);
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_get_IV_length(int32_t transformation_id, int32_t native_id) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	LLSEC_UNUSED_PARAM(transformation_id);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;
	return cipher_ctx->iv_length;
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, uint8_t *key, int32_t key_length,
                               uint8_t *iv, int32_t iv_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);

	int32_t return_code = LLSEC_SUCCESS;
	void *native_id = NULL;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;

	if (iv_length <= 0) {
		(void)SNI_throwNativeException(iv_length, "LLSEC_CIPHER_IMPL_init invalid iv length");
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		return_code = transformation->init(transformation_id, (void **)&native_id, is_decrypting, key, key_length, iv,
		                                   iv_length);
		if (LLSEC_SUCCESS != return_code) {
			(void)SNI_throwNativeException(return_code, "LLSEC_CIPHER_IMPL_init failed");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_OK != SNI_registerResource(native_id, transformation->close, NULL)) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't register SNI native resource");
			transformation->close((void *)native_id);
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.6]: Abstract data type for SNI usage
		return_code = (int32_t)(native_id);
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_decrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer, int32_t buffer_offset,
                                  int32_t buffer_length, uint8_t *output, int32_t output_offset) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	int32_t return_code = LLSEC_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	int rc = transformation->decrypt((void *)native_id, &buffer[buffer_offset], buffer_length, &output[output_offset]);
	if (LLSEC_SUCCESS != rc) {
		(void)SNI_throwNativeException(rc, "LLSEC_CIPHER_IMPL_decrypt failed");
		return_code = LLSEC_ERROR;
	} else {
		return_code = buffer_length;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_encrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer, int32_t buffer_offset,
                                  int32_t buffer_length, uint8_t *output, int32_t output_offset) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	int32_t return_code = LLSEC_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	int rc = transformation->encrypt((void *)native_id, &buffer[buffer_offset], buffer_length, &output[output_offset]);
	if (LLSEC_SUCCESS != rc) {
		(void)SNI_throwNativeException(rc, "LLSEC_CIPHER_IMPL_encrypt failed");
		return_code = LLSEC_ERROR;
	} else {
		return_code = buffer_length;
	}
	return return_code;
}

// See the header file for the function documentation
void LLSEC_CIPHER_IMPL_close(int32_t transformation_id, int32_t native_id) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;

	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	transformation->close((void *)native_id);
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	if (SNI_OK != SNI_unregisterResource((void *)native_id, (SNI_closeFunction)transformation->close)) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "Can't unregister SNI native resource");
	}
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_get_close_id(int32_t transformation_id) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)transformation->close;
}
