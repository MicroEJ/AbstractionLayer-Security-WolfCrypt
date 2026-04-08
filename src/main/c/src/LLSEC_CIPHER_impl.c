/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Cipher (encryption/decryption).
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_CIPHER_impl.h>
#include <LLSEC_ERRORS.h>
#include <LLSEC_common.h>

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

#define AES_CCM_BLOCK_BITS    (128u)
#define AES_CCM_BLOCK_BYTES   (AES_CCM_BLOCK_BITS / 8u)
#define AES_CCM_IV_SIZE       AES_BLOCK_SIZE

#define AES_CTR_BLOCK_BITS    (128u)
#define AES_CTR_BLOCK_BYTES   (AES_CTR_BLOCK_BITS / 8u)
#define AES_CTR_IV_SIZE       AES_BLOCK_SIZE

#define DES_CBC_BLOCK_BITS    (64u)
#define DES_CBC_BLOCK_BYTES   (DES_CBC_BLOCK_BITS / 8u)
#define DES_CBC_IV_SIZE       DES_BLOCK_SIZE

#define AES_GCM_BLOCK_BITS    (128u)
#define AES_GCM_BLOCK_BYTES   (AES_GCM_BLOCK_BITS / 8u)
#define AES_GCM_IV_SIZE       AES_BLOCK_SIZE

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef int (*LLSEC_CIPHER_init)(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                 uint8_t *iv, int32_t iv_length, int32_t tag_length);
typedef int (*LLSEC_CIPHER_decrypt)(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                    uint8_t doFinal);
typedef int (*LLSEC_CIPHER_encrypt)(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                    uint8_t doFinal);
typedef void (*LLSEC_CIPHER_set_iv)(void *native_id, const uint8_t *iv, int32_t iv_length);
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
#ifndef NO_DES3
	Des3 des3_ctx;
#endif // NO_DES3
} cipher_ctx;

#ifndef LLSEC_CIPHER_MAX_IV_LENGTH
#define LLSEC_CIPHER_MAX_IV_LENGTH AES_BLOCK_SIZE
#endif // LLSEC_CIPHER_MAX_IV_LENGTH

#ifndef LLSEC_CIPHER_MAX_TAG_LENGTH
#define LLSEC_CIPHER_MAX_TAG_LENGTH AES_BLOCK_SIZE
#endif // LLSEC_CIPHER_MAX_TAG_LENGTH

#ifndef LLSEC_CIPHER_MAX_AAD_LENGTH
#define LLSEC_CIPHER_MAX_AAD_LENGTH AES_BLOCK_SIZE
#endif // LLSEC_CIPHER_MAX_AAD_LENGTH

typedef struct {
	LLSEC_CIPHER_transformation *transformation;
	// cppcheck-suppress [misra-c2012-19.2]: Generic justification, is useful when designing C library.
	cipher_ctx wolfcrypt_ctx;
	int32_t iv_length;
	uint8_t iv[LLSEC_CIPHER_MAX_IV_LENGTH];
	int32_t tag_length;
	int32_t aad_length;
	uint8_t aad[LLSEC_CIPHER_MAX_AAD_LENGTH];
} LLSEC_CIPHER_ctx;

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

// cppcheck-suppress [misra-c2012-2.7] : false positive, parameters used in optional debug trace.
static void llsec_cipher_debug_print_hex(const char *name, void *p, int len) {
	LLSEC_CIPHER_DEBUG_TRACE("\t\t%s = ", name);
	for (int i = 0; i < len; i++) {
		LLSEC_CIPHER_DEBUG_TRACE("%02X", ((uint8_t *)p)[i]);
	}
	LLSEC_CIPHER_DEBUG_TRACE("\n");
}

static int LLSEC_CIPHER_aes_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                 uint8_t *iv, int32_t iv_length, int32_t tag_length);
#ifndef NO_DES3
static int LLSEC_CIPHER_des3cbc_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                     uint8_t *iv, int32_t iv_length, int32_t tag_length);
#endif // NO_DES3
static int wolfcrypt_aes_cbc_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                            uint8_t doFinal);
#ifndef NO_DES3
static int wolfcrypt_des3_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                         uint8_t doFinal);
#endif // NO_DES3
static int wolfcrypt_aes_cbc_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                            uint8_t doFinal);
#ifndef NO_DES3
static int wolfcrypt_des3_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                         uint8_t doFinal);
#endif // NO_DES3
static void wolfcrypt_aes_cipher_set_iv(void *native_id, const uint8_t *iv, int32_t iv_length);
#ifndef NO_DES3
static void wolfcrypt_des3_cipher_set_iv(void *native_id, const uint8_t *iv, int32_t iv_length);
#endif // NO_DES3
static void wolfcrypt_aes_cipher_close(void *native_id);
#ifndef NO_DES3
static void wolfcrypt_des3_cipher_close(void *native_id);
#endif // NO_DES3

#ifndef NO_AES

/**
 * @brief  Creates and initializes the Wolfcrypt native structure to use AES ciphers.
 *
 * @param[in]  transformation_id  Pointer to the transformation description
 * @param[out]  native_id   Pointer pointer to the AES native structure.
 * @param[in]   is_decrypting  Cipher direction : '1' for decrypting, '0' for encrypting.
 * @param[in]   key_id  Pointer to a buffer containing the key for the AES cipher.
 * @param[in]   iv Pointer to the initialization vector used to initialize the key
 * @param[in]   iv_length Size of the initialization vector (in bytes)
 * @param[in]   tag_length Size of the tag, for GCM only (in bytes).
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int LLSEC_CIPHER_aes_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                 uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);

	LLSEC_CIPHER_ctx *cipher_ctx;
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llsec_wolfssl_get_heap();
	LLSEC_key *key = (LLSEC_key *)key_id;
	LLSEC_secret_key *secret_key = (LLSEC_secret_key *)key->secret_key;

	cipher_ctx = (LLSEC_CIPHER_ctx *)llsec_calloc(1, (int32_t)sizeof(LLSEC_CIPHER_ctx) - 1 + AES_BLOCK_SIZE);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	cipher_ctx->transformation = (LLSEC_CIPHER_transformation *)transformation_id;
	cipher_ctx->transformation->set_iv((void *)cipher_ctx, iv, iv_length);
	cipher_ctx->tag_length = tag_length;
	cipher_ctx->aad_length = 0;

	wolfcrypt_rc = wc_AesInit(&cipher_ctx->wolfcrypt_ctx.aes_ctx, pHint, INVALID_DEVID);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
		LLSEC_CIPHER_DEBUG_TRACE("wc_AesInit() => %s\n", llsec_wc_error_message(wolfcrypt_rc));
	}

	if (LLSEC_SUCCESS == return_code) {
		int dir;
		if ((uint8_t)0 != is_decrypting) {
			dir = AES_DECRYPTION;
		} else {
			dir = AES_ENCRYPTION;
		}
		wolfcrypt_rc = wc_AesSetKey(&cipher_ctx->wolfcrypt_ctx.aes_ctx, secret_key->key, secret_key->key_length, iv,
		                            dir);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			return_code = LLSEC_ERROR;
			LLSEC_CIPHER_DEBUG_TRACE("wc_AesSetKey() => %s\n", llsec_wc_error_message(wolfcrypt_rc));
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		*native_id = cipher_ctx;
	} else {
		wc_AesFree(&cipher_ctx->wolfcrypt_ctx.aes_ctx);
		llsec_free(cipher_ctx);
	}
	return return_code;
}

#ifdef WOLFSSL_AES_COUNTER
static int LLSEC_CIPHER_aes_ctr_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                     uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLSEC_UNUSED_PARAM(is_decrypting);
	return LLSEC_CIPHER_aes_init(transformation_id, native_id, 0, key_id, iv, iv_length, tag_length); // in CTR mode,
	                                                                                                  // always
	                                                                                                  // configure for
	                                                                                                  // encryption
}

#endif // WOLFSSL_AES_COUNTER
#ifdef HAVE_AESCCM
static int LLSEC_CIPHER_aes_ccm_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                     uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	LLSEC_UNUSED_PARAM(is_decrypting);

	LLSEC_CIPHER_ctx *cipher_ctx;
	int32_t return_code = LLSEC_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llsec_wolfssl_get_heap();
	LLSEC_key *key = (LLSEC_key *)key_id;
	LLSEC_secret_key *secret_key = (LLSEC_secret_key *)key->secret_key;

	cipher_ctx = (LLSEC_CIPHER_ctx *)llsec_calloc(1, (int32_t)sizeof(LLSEC_CIPHER_ctx) - 1 + AES_BLOCK_SIZE);
	if (NULL == cipher_ctx) {
		return_code = LLSEC_ERROR;
		LLSEC_CIPHER_DEBUG_TRACE("Could not allocate memory for cipher_ctx\n");
	}

	int wolfcrypt_rc;
	if (LLSEC_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		cipher_ctx->transformation = (LLSEC_CIPHER_transformation *)transformation_id;
		cipher_ctx->transformation->set_iv((void *)cipher_ctx, iv, iv_length);
		cipher_ctx->tag_length = tag_length;
		cipher_ctx->aad_length = 0;

		wolfcrypt_rc = wc_AesInit(&cipher_ctx->wolfcrypt_ctx.aes_ctx, pHint, INVALID_DEVID);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			return_code = (BAD_FUNC_ARG ==
			               wolfcrypt_rc) ? (int32_t)LLSEC_ERROR_INVALID_PARAMETER : (int32_t)LLSEC_ERROR;
			LLSEC_CIPHER_DEBUG_TRACE("wc_AesInit() => %s\n", llsec_wc_error_message(wolfcrypt_rc));
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		wolfcrypt_rc = wc_AesCcmSetKey(&cipher_ctx->wolfcrypt_ctx.aes_ctx, secret_key->key, secret_key->key_length);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			return_code = (BAD_FUNC_ARG ==
			               wolfcrypt_rc) ? (int32_t)LLSEC_ERROR_INVALID_PARAMETER : (int32_t)LLSEC_ERROR;
			LLSEC_CIPHER_DEBUG_TRACE("wc_AesCcmSetKey() => %s\n", llsec_wc_error_message(wolfcrypt_rc));
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		*native_id = cipher_ctx;
	} else {
		wc_AesFree(&cipher_ctx->wolfcrypt_ctx.aes_ctx);
		llsec_free(cipher_ctx);
	}
	return return_code;
}

#endif // HAVE_AESCCM
#endif // NO_AES
#ifndef NO_DES3
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
static int LLSEC_CIPHER_des3cbc_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                     uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s %d\n", __func__, is_decrypting);

	LLSEC_CIPHER_ctx *cipher_ctx;
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llsec_wolfssl_get_heap();
	LLSEC_key *key = (LLSEC_key *)key_id;
	LLSEC_secret_key *secret_key = (LLSEC_secret_key *)key->secret_key;

	cipher_ctx = llsec_calloc(1, (int32_t)sizeof(LLSEC_CIPHER_ctx) - 1 + DES_CBC_IV_SIZE);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	cipher_ctx->transformation = (LLSEC_CIPHER_transformation *)transformation_id;
	cipher_ctx->transformation->set_iv((void *)cipher_ctx, iv, iv_length);
	cipher_ctx->tag_length = tag_length;
	cipher_ctx->aad_length = 0;

	wc_Des3Init(&cipher_ctx->wolfcrypt_ctx.des3_ctx, pHint, INVALID_DEVID);

	if ((uint8_t)0 != is_decrypting) {
		wolfcrypt_rc = wc_Des3_SetKey(&cipher_ctx->wolfcrypt_ctx.des3_ctx, secret_key->key, iv, DES_DECRYPTION);
		LLSEC_CIPHER_DEBUG_TRACE("%s mbedtls_des3_set3key_dec (rc = %d)\n", __func__, wolfcrypt_rc);
	} else {
		wolfcrypt_rc = wc_Des3_SetKey(&cipher_ctx->wolfcrypt_ctx.des3_ctx, secret_key->key, iv, DES_ENCRYPTION);
		LLSEC_CIPHER_DEBUG_TRACE("%s mbedtls_des3_set3key_enc (rc = %d)\n", __func__, wolfcrypt_rc);
	}

	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		*native_id = cipher_ctx;
	} else {
		wc_Des3Free(&cipher_ctx->wolfcrypt_ctx.des3_ctx);
		llsec_free(cipher_ctx);
	}
	return return_code;
}

#endif // NO_DES3

/**
 * @brief Decrypts a data buffer with AES and stores them in an output buffer.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt AES native structure.
 * @param[in]  buffer Pointer to the data buffer to decrypt.
 * @param[in]  buffer_length Size of the data to decrypt (in bytes).
 * @param[in]  output Pointer to the buffer to store decrypted bytes.
 * @param[in]  doFinal '1' if this is a final operation, '0' otherwise.
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int wolfcrypt_aes_cbc_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                            uint8_t doFinal) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);

	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	LLSEC_UNUSED_PARAM(doFinal);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_AesCbcDecrypt(&cipher_ctx->wolfcrypt_ctx.aes_ctx, output, buffer, buffer_length);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

#ifdef HAVE_AESCCM
static int wolfcrypt_aes_ccm_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                     uint8_t doFinal) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);
	LLSEC_UNUSED_PARAM(doFinal);

	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	Aes *aes = &cipher_ctx->wolfcrypt_ctx.aes_ctx;
	byte *plaintext = output;
	byte *ciphertext = buffer;
	word32 ciphertext_len = buffer_length - cipher_ctx->tag_length; // input buffer is the concatenation of the
	                                                                // ciphertext and the auth tag
	byte *iv = cipher_ctx->iv;
	word32 iv_len = cipher_ctx->iv_length;
	byte *tag = buffer + buffer_length - cipher_ctx->tag_length; // input buffer is the concatenation of the ciphertext
	                                                             // and the auth tag
	word32 tag_len = cipher_ctx->tag_length;
	byte *aad = cipher_ctx->aad;
	word32 aad_len = cipher_ctx->aad_length;  // input buffer is the concatenation of the ciphertext and the auth tag

	wolfcrypt_rc = wc_AesCcmDecrypt(aes, plaintext, ciphertext, ciphertext_len, iv, iv_len, tag, tag_len, aad, aad_len);
	LLSEC_CIPHER_DEBUG_TRACE("\twc_AesCcmDecrypt(%p, %p, %p, %d, %p, %d, %p, %d, %p, %d) => %s\n",
	                         aes, plaintext, ciphertext, ciphertext_len, iv, iv_len, tag, tag_len, aad, aad_len,
	                         llsec_wc_error_message(wolfcrypt_rc));
	llsec_cipher_debug_print_hex("[in] ciphertext", ciphertext, ciphertext_len);
	llsec_cipher_debug_print_hex("[in] iv        ", iv, iv_len);
	llsec_cipher_debug_print_hex("[in] tag       ", tag, tag_len);
	llsec_cipher_debug_print_hex("[in] aad       ", aad, aad_len);
	llsec_cipher_debug_print_hex("[out] plaintext", plaintext, ciphertext_len);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

#endif // HAVE_AESCCM

#ifndef NO_DES3
/**
 * @brief Decrypts a data buffer with DES and stores them in an output buffer.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt DES native structure.
 * @param[in]  buffer Pointer to the data buffer to decrypt.
 * @param[in]  buffer_length Size of the data to decrypt (in bytes).
 * @param[in]  output Pointer to the buffer to store decrypted bytes.
 * @param[in]  doFinal '1' if this is a final operation, '0' otherwise.
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int wolfcrypt_des3_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                         uint8_t doFinal) {
	LLSEC_CIPHER_DEBUG_TRACE("%s \n", __func__);

	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	LLSEC_UNUSED_PARAM(doFinal);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_Des3_CbcDecrypt(&cipher_ctx->wolfcrypt_ctx.des3_ctx, output, buffer, buffer_length);

	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}
	return return_code;
}

#endif // NO_DES3

#ifdef HAVE_AESGCM
static int wolfcrypt_aes_gcm_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                     uint8_t doFinal) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLSEC_UNUSED_PARAM(doFinal);

	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	Aes *aes = &cipher_ctx->wolfcrypt_ctx.aes_ctx;
	byte *plaintext = output;
	byte *ciphertext = buffer;
	word32 ciphertext_len = buffer_length - cipher_ctx->tag_length; // input buffer is the concatenation of the
	                                                                // ciphertext and the auth tag
	byte *iv = cipher_ctx->iv;
	word32 iv_len = cipher_ctx->iv_length;
	byte *tag = buffer + buffer_length - cipher_ctx->tag_length; // input buffer is the concatenation of the ciphertext
	                                                             // and the auth tag
	word32 tag_len = cipher_ctx->tag_length;
	byte *aad = cipher_ctx->aad;
	word32 aad_len = cipher_ctx->aad_length;  // input buffer is the concatenation of the ciphertext and the auth tag

	wolfcrypt_rc = wc_AesGcmDecrypt(aes, plaintext, ciphertext, ciphertext_len, iv, iv_len, tag, tag_len, aad, aad_len);
	LLSEC_CIPHER_DEBUG_TRACE("\twc_AesGcmDecrypt(%p, %p, %p, %d, %p, %d, %p, %d, %p, %d) => %s\n",
	                         aes, plaintext, ciphertext, ciphertext_len, iv, iv_len, tag, tag_len, aad, aad_len,
	                         llsec_wc_error_message(wolfcrypt_rc));
	llsec_cipher_debug_print_hex("[in] ciphertext", ciphertext, ciphertext_len);
	llsec_cipher_debug_print_hex("[in] iv        ", iv, iv_len);
	llsec_cipher_debug_print_hex("[in] tag       ", tag, tag_len);
	llsec_cipher_debug_print_hex("[in] aad       ", aad, aad_len);
	llsec_cipher_debug_print_hex("[out] plaintext", plaintext, ciphertext_len);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

#endif // HAVE_AESGCM

#ifdef HAVE_AES_CBC
static int wolfcrypt_aes_cbc_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                            uint8_t doFinal) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	LLSEC_UNUSED_PARAM(doFinal);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_AesCbcEncrypt(&cipher_ctx->wolfcrypt_ctx.aes_ctx, output, buffer, buffer_length);

	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

#endif // HAVE_AES_CBC
#ifdef HAVE_AESCCM
static int wolfcrypt_aes_ccm_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                     uint8_t doFinal) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLSEC_UNUSED_PARAM(doFinal);

	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	Aes *aes = &cipher_ctx->wolfcrypt_ctx.aes_ctx;
	byte *ciphertext = output;
	byte *plaintext = buffer;
	word32 plaintext_len = buffer_length;
	byte *iv = cipher_ctx->iv;
	word32 iv_len = cipher_ctx->iv_length;
	byte *tag = output + buffer_length; // auth tag is added at the end of the output buffer, after ciphertext
	word32 tag_len = cipher_ctx->tag_length;
	byte *aad = cipher_ctx->aad;
	word32 aad_len = cipher_ctx->aad_length;

	wolfcrypt_rc = wc_AesCcmEncrypt(aes, ciphertext, plaintext, plaintext_len, iv, iv_len, tag, tag_len, aad, aad_len);
	LLSEC_CIPHER_DEBUG_TRACE("\twc_AesCcmEncrypt(%p, %p, %p, %d, %p, %d, %p, %d, %p, %d) => %s\n",
	                         aes, ciphertext, plaintext, plaintext_len, iv, iv_len, tag, tag_len, aad, aad_len,
	                         llsec_wc_error_message(wolfcrypt_rc));
	llsec_cipher_debug_print_hex("[in] plaintext  ", plaintext, plaintext_len);
	llsec_cipher_debug_print_hex("[in] iv         ", iv, iv_len);
	llsec_cipher_debug_print_hex("[in] aad        ", aad, aad_len);
	llsec_cipher_debug_print_hex("[out] ciphertext", ciphertext, plaintext_len);
	llsec_cipher_debug_print_hex("[out] tag       ", tag, tag_len);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

#endif // HAVE_AESCCM
#ifdef WOLFSSL_AES_COUNTER
static int wolfcrypt_aes_ctr_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                     uint8_t doFinal) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	LLSEC_UNUSED_PARAM(doFinal);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_AesCtrEncrypt(&cipher_ctx->wolfcrypt_ctx.aes_ctx, output, buffer, buffer_length);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
		LLSEC_CIPHER_DEBUG_TRACE("wc_AesCtrEncrypt() failed with error %d\n", wolfcrypt_rc);
	}

	return return_code;
}

#endif // WOLFSSL_AES_COUNTER
#ifndef NO_DES3
/**
 * @brief Encryptes a data buffer with DES and stores them in an output buffer.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt DES native structure.
 * @param[in]  buffer Pointer to the data buffer to encrypt.
 * @param[in]  buffer_length Size of the data to encrypt (in bytes).
 * @param[in]  output Pointer to the buffer to store encrypted bytes.
 * @param[in]  doFinal '1' if this is a final operation, '0' otherwise.
 *
 * @return LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int wolfcrypt_des3_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                         uint8_t doFinal) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLSEC_UNUSED_PARAM(doFinal);

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

#endif // NO_DES3
#ifdef HAVE_AESGCM
static int wolfcrypt_aes_gcm_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                     uint8_t doFinal) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLSEC_UNUSED_PARAM(doFinal);

	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	Aes *aes = &cipher_ctx->wolfcrypt_ctx.aes_ctx;
	byte *ciphertext = output;
	byte *plaintext = buffer;
	word32 plaintext_len = buffer_length;
	byte *iv = cipher_ctx->iv;
	word32 iv_len = cipher_ctx->iv_length;
	byte *tag = output + buffer_length; // auth tag is added at the end of the output buffer, after ciphertext
	word32 tag_len = cipher_ctx->tag_length;
	byte *aad = cipher_ctx->aad;
	word32 aad_len = cipher_ctx->aad_length;

	wolfcrypt_rc = wc_AesGcmEncrypt(aes, ciphertext, plaintext, plaintext_len, iv, iv_len, tag, tag_len, aad, aad_len);
	LLSEC_CIPHER_DEBUG_TRACE("\twc_AesGcmEncrypt(%p, %p, %p, %d, %p, %d, %p, %d, %p, %d) => %s\n",
	                         aes, ciphertext, plaintext, plaintext_len, iv, iv_len, tag, tag_len, aad, aad_len,
	                         llsec_wc_error_message(wolfcrypt_rc));
	llsec_cipher_debug_print_hex("[in] plaintext  ", plaintext, plaintext_len);
	llsec_cipher_debug_print_hex("[in] iv         ", iv, iv_len);
	llsec_cipher_debug_print_hex("[in] aad        ", aad, aad_len);
	llsec_cipher_debug_print_hex("[out] ciphertext", ciphertext, plaintext_len);
	llsec_cipher_debug_print_hex("[out] tag       ", tag, tag_len);
	if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLSEC_ERROR;
	}

	return return_code;
}

#endif // HAVE_AESGCM

/**
 * @brief Set the initialization vector of an Wolfcrypt AES key.
 *
 * @param[in]  native_id Pointer to Wolfcrypt AES key native structure.
 * @param[in]  iv Pointer to the buffer containing the initialization vector.
 * @param[in]  iv_length Size of the initialization vector (in bytes).
 *
 */
static void wolfcrypt_aes_cipher_set_iv(void *native_id, const uint8_t *iv, int32_t iv_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;
	cipher_ctx->iv_length = iv_length; // at this point, we know iv_length < MAX_IV_LENGTH
	llsec_memcpy(cipher_ctx->iv, iv, iv_length);
	wc_AesSetIV(&cipher_ctx->wolfcrypt_ctx.aes_ctx, cipher_ctx->iv);
}

#ifndef NO_DES3
/**
 * @brief Set the initialization vector of an Wolfcrypt DES key.
 *
 * @param[in]  native_id Pointer to Wolfcrypt AES key native structure.
 * @param[in]  iv Pointer to the buffer containing the initialization vector.
 * @param[in]  iv_length Size of the initialization vector (in bytes).
 *
 */
static void wolfcrypt_des3_cipher_set_iv(void *native_id, const uint8_t *iv, int32_t iv_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;
	cipher_ctx->iv_length = iv_length;
	llsec_memcpy(cipher_ctx->iv, iv, cipher_ctx->iv_length);
	wc_Des3_SetIV(&cipher_ctx->wolfcrypt_ctx.des3_ctx, cipher_ctx->iv);
}

#endif // NO_DES3

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
	llsec_free(native_id);
}

#ifndef NO_DES3
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
	llsec_free(native_id);
}

#endif // NO_DES3

// --------------------------------------------------------------------------------
// LLSEC_CIPHER_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_get_transformation_description(uint8_t *transformation_name,
                                                         LLSEC_CIPHER_transformation_desc *transformation_desc) {
	LLSEC_CIPHER_DEBUG_TRACE("%s(transf=\"%s\")\n", __func__, transformation_name);

	static LLSEC_CIPHER_transformation available_transformations[] = {
#ifdef HAVE_AES_CBC
		{
			.name = "AES/CBC/NoPadding",
			.init = LLSEC_CIPHER_aes_init,
			.decrypt = wolfcrypt_aes_cbc_cipher_decrypt,
			.encrypt = wolfcrypt_aes_cbc_cipher_encrypt,
			.close = wolfcrypt_aes_cipher_close,
			.set_iv = wolfcrypt_aes_cipher_set_iv,
			{
				.block_size = AES_CBC_BLOCK_BYTES,
				.unit_bytes = AES_CBC_BLOCK_BYTES,
				.cipher_mode = CBC_MODE,
			},
		},
#endif // HAVE_AES_CBC
#ifdef HAVE_AESCCM
		{
			.name = "AES/CCM/NoPadding",
			.init = LLSEC_CIPHER_aes_ccm_init, // always configure for encryption regardless of is_decrypting parameter
			.decrypt = wolfcrypt_aes_ccm_decrypt,
			.encrypt = wolfcrypt_aes_ccm_encrypt,
			.close = wolfcrypt_aes_cipher_close,
			.set_iv = wolfcrypt_aes_cipher_set_iv,
			{
				.block_size = AES_CCM_BLOCK_BYTES,
				.unit_bytes = 1,
				.cipher_mode = GCM_MODE, // use GCM mode for CCM
			},
		},
#endif // HAVE_AESCCM
#ifdef WOLFSSL_AES_COUNTER
		{
			.name = "AES/CTR/NoPadding",
			.init = LLSEC_CIPHER_aes_ctr_init,     // always configure for encryption regardless of is_decrypting
			                                       // parameter
			.decrypt = wolfcrypt_aes_ctr_encrypt,     // same function for encrypt & decrypt
			.encrypt = wolfcrypt_aes_ctr_encrypt,
			.close = wolfcrypt_aes_cipher_close,
			.set_iv = wolfcrypt_aes_cipher_set_iv,
			{
				.block_size = AES_CTR_BLOCK_BYTES,
				.unit_bytes = 1,
				.cipher_mode = CTR_MODE,
			},
		},
#endif // WOLFSSL_AES_COUNTER
#ifndef NO_DES3
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
		},
#endif // NO_DES3
#ifdef HAVE_AESGCM
		{
			.name = "AES/GCM/NoPadding",
			.init = LLSEC_CIPHER_aes_init,
			.decrypt = wolfcrypt_aes_gcm_decrypt,
			.encrypt = wolfcrypt_aes_gcm_encrypt,
			.close = wolfcrypt_aes_cipher_close,
			.set_iv = wolfcrypt_aes_cipher_set_iv,
			{
				.block_size = AES_GCM_BLOCK_BYTES,
				.unit_bytes = AES_GCM_BLOCK_BYTES,
				.cipher_mode = GCM_MODE,
			},
		},
#endif // HAVE_AESGCM
	};

	int32_t return_code = LLSEC_SUCCESS;
	int32_t nb_transformations = sizeof(available_transformations) / sizeof(LLSEC_CIPHER_transformation);
	LLSEC_CIPHER_transformation *transformation = &available_transformations[0];

	while (--nb_transformations >= 0) {
		if (strcmp((const char *)transformation_name, transformation->name) == 0) {
			llsec_memcpy(transformation_desc, &(transformation->description), sizeof(LLSEC_CIPHER_transformation_desc));
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
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLSEC_UNUSED_PARAM(nativeTransformationId);
	LLSEC_UNUSED_PARAM(nativeId);
	return LLSEC_SUCCESS;
}

// See the header file for the function documentation
void LLSEC_CIPHER_IMPL_get_IV(int32_t transformation_id, int32_t native_id, uint8_t *iv, int32_t iv_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLSEC_UNUSED_PARAM(transformation_id);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	const LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;
	llsec_memcpy(iv, cipher_ctx->iv, iv_length);
}

// See the header file for the function documentation
void LLSEC_CIPHER_IMPL_set_IV(int32_t transformation_id, int32_t native_id, uint8_t *iv, int32_t iv_length) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_CIPHER_DEBUG_TRACE("%s(cipher=%p, iv=%p)", __func__, (void *)native_id, iv);
	for (int i = 0; i < iv_length; i++) {
		LLSEC_CIPHER_DEBUG_TRACE("%02X", iv[i]);
	}
	LLSEC_CIPHER_DEBUG_TRACE(")\n");
	if (iv_length > LLSEC_CIPHER_MAX_IV_LENGTH) {
		llsec_throw(LLSEC_ERROR, "Max IV length exceeded");
	} else {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;
		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		transformation->set_iv((void *)native_id, iv, iv_length);
	}
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_get_IV_length(int32_t transformation_id, int32_t native_id) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLSEC_UNUSED_PARAM(transformation_id);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	const LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;
	return cipher_ctx->iv_length;
}

// See the header file for the function documentation
void LLSEC_CIPHER_IMPL_update_AAD(int32_t transformation_id, int32_t native_id, uint8_t *aad, int32_t offset,
                                  int32_t aad_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLSEC_UNUSED_PARAM(transformation_id);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_ctx *cipher_ctx = (LLSEC_CIPHER_ctx *)native_id;

	if (aad_length > LLSEC_CIPHER_MAX_AAD_LENGTH) {
		llsec_throw(aad_length, "Invalid AAD length");
	} else {
		cipher_ctx->aad_length = aad_length;
		llsec_memcpy(cipher_ctx->aad, &aad[offset], aad_length);
	}
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, int32_t key,
                               uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);

	int32_t return_code = LLSEC_SUCCESS;
	void *native_id = NULL;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;

	LLSEC_CIPHER_DEBUG_TRACE("transf=\"%s\", ", transformation->name);
	LLSEC_CIPHER_DEBUG_TRACE("mode=\"%s\", ", is_decrypting ? "DECRYPT" : "ENCRYPT");
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_CIPHER_DEBUG_TRACE("key=%p,", (void *)key);
	LLSEC_CIPHER_DEBUG_TRACE("iv=");
	for (int i = 0; i < iv_length; i++) {
		LLSEC_CIPHER_DEBUG_TRACE("%02X", iv[i]);
	}
	LLSEC_CIPHER_DEBUG_TRACE(", tag_length=%d", tag_length);
	LLSEC_CIPHER_DEBUG_TRACE(")\n");

	if ((iv_length <= 0) || (iv_length > LLSEC_CIPHER_MAX_IV_LENGTH)) {
		llsec_throw(iv_length, "Invalid IV length");
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		if (tag_length > LLSEC_CIPHER_MAX_TAG_LENGTH) {
			llsec_throw(tag_length, "Invalid tag length");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		return_code = transformation->init(transformation_id, &native_id, is_decrypting, key, iv, iv_length,
		                                   tag_length);
		if (LLSEC_SUCCESS != return_code) {
			llsec_throw(return_code, "LLSEC_CIPHER_IMPL_init failed");
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
		// cppcheck-suppress [misra-c2012-11.6]: Abstract data type for SNI usage
		return_code = (int32_t)(native_id);
		LLSEC_CIPHER_DEBUG_TRACE("%s() => %p\n", __func__, native_id);
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_decrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer, int32_t buffer_offset,
                                  int32_t buffer_length, uint8_t *output, int32_t output_offset, uint8_t doFinal) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_CIPHER_DEBUG_TRACE("%s(cipher=%p, inBuf=%p, inOff=%d, inLen=%d, outBuf=%p, outOff=%d, doFinal=%s)\n",
	                         __func__, (void *)native_id, buffer, buffer_offset, buffer_length, output, output_offset,
	                         (doFinal == 0u) ? "false" : "true");

	int32_t return_code = LLSEC_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	int rc = transformation->decrypt((void *)native_id, &buffer[buffer_offset], buffer_length, &output[output_offset],
	                                 doFinal);
	if (LLSEC_SUCCESS != rc) {
		llsec_throw(rc, "LLSEC_CIPHER_IMPL_decrypt failed");
		return_code = LLSEC_ERROR;
	} else {
		return_code = SNI_getArrayLength(output); // if AEAD, output is smaller than input (smaller by tag length),
		                                          // otherwise, should be equal to buffer_length (input);
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_encrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer, int32_t buffer_offset,
                                  int32_t buffer_length, uint8_t *output, int32_t output_offset, uint8_t doFinal) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_CIPHER_DEBUG_TRACE("%s(cipher=%p, inBuf=%p, inOff=%d, inLen=%d, outBuf=%p, outOff=%d, doFinal=%s)\n",
	                         __func__, (void *)native_id, buffer, buffer_offset, buffer_length, output, output_offset,
	                         (doFinal == 0u) ? "false" : "true");
	int32_t return_code = LLSEC_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	int rc = transformation->encrypt((void *)native_id, &buffer[buffer_offset], buffer_length, &output[output_offset],
	                                 doFinal);
	if (LLSEC_SUCCESS != rc) {
		llsec_throw(rc, "LLSEC_CIPHER_IMPL_encrypt failed");
		return_code = LLSEC_ERROR;
	} else {
		return_code = SNI_getArrayLength(output); // if AEAD, should include tag, otherwise, should be equal to
		                                          // buffer_length (input)
	}
	return return_code;
}

// See the header file for the function documentation
void LLSEC_CIPHER_IMPL_close(int32_t transformation_id, int32_t native_id) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;

	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	transformation->close((void *)native_id);
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	if (SNI_OK != SNI_unregisterResource((void *)native_id, (SNI_closeFunction)transformation->close)) {
		llsec_throw(LLSEC_ERROR, "Can't unregister SNI native resource");
	}
}

// See the header file for the function documentation
int32_t LLSEC_CIPHER_IMPL_get_close_id(int32_t transformation_id) {
	LLSEC_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_CIPHER_transformation *transformation = (LLSEC_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)transformation->close;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
