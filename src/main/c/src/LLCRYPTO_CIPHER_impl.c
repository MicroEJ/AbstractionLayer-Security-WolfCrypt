/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - Cipher (encryption/decryption).
 * @author MicroEJ Developer Team
 * @version 2.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_CIPHER_impl.h>
#include <LLCRYPTO_ERRORS.h>
#include <LLCRYPTO_common.h>

#include <sni.h>
#include <stdbool.h>
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

typedef int (*LLCRYPTO_CIPHER_init)(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                    uint8_t *iv, int32_t iv_length, int32_t tag_length);
typedef int (*LLCRYPTO_CIPHER_decrypt)(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                       uint8_t doFinal);
typedef int (*LLCRYPTO_CIPHER_encrypt)(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                       uint8_t doFinal);
typedef void (*LLCRYPTO_CIPHER_set_iv)(void *native_id, const uint8_t *iv, int32_t iv_length);
typedef void (*LLCRYPTO_CIPHER_close)(void *native_id);

typedef struct {
	char *name; // the name of the transformation
	LLCRYPTO_CIPHER_init init;
	LLCRYPTO_CIPHER_decrypt decrypt;
	LLCRYPTO_CIPHER_encrypt encrypt;
	LLCRYPTO_CIPHER_close close;
	LLCRYPTO_CIPHER_set_iv set_iv;
	LLCRYPTO_CIPHER_transformation_desc description;
} LLCRYPTO_CIPHER_transformation;

// cppcheck-suppress [misra-c2012-19.2]: Generic justification, is useful when designing C library.
typedef union {
	Aes aes_ctx;
#ifndef NO_DES3
	Des3 des3_ctx;
#endif // NO_DES3
} cipher_ctx;

#ifndef LLCRYPTO_CIPHER_MAX_IV_LENGTH
#define LLCRYPTO_CIPHER_MAX_IV_LENGTH AES_BLOCK_SIZE
#endif // LLCRYPTO_CIPHER_MAX_IV_LENGTH

#ifndef LLCRYPTO_CIPHER_MAX_TAG_LENGTH
#define LLCRYPTO_CIPHER_MAX_TAG_LENGTH AES_BLOCK_SIZE
#endif // LLCRYPTO_CIPHER_MAX_TAG_LENGTH

/* Longest additional authenticated data accepted by an AEAD cipher, in bytes. One AES block is too short for
 * the headers a protocol authenticates; the context is allocated per cipher, so the cost is this size per open cipher.
 */
#ifndef LLCRYPTO_CIPHER_MAX_AAD_LENGTH
#define LLCRYPTO_CIPHER_MAX_AAD_LENGTH (256)
#endif // LLCRYPTO_CIPHER_MAX_AAD_LENGTH

typedef struct {
	LLCRYPTO_CIPHER_transformation *transformation;
	// cppcheck-suppress [misra-c2012-19.2]: Generic justification, is useful when designing C library.
	cipher_ctx wolfcrypt_ctx;
	int32_t iv_length;
	uint8_t iv[LLCRYPTO_CIPHER_MAX_IV_LENGTH];
	int32_t tag_length;
	int32_t aad_length;
	uint8_t aad[LLCRYPTO_CIPHER_MAX_AAD_LENGTH];
} LLCRYPTO_CIPHER_ctx;

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

// cppcheck-suppress [misra-c2012-2.7] : false positive, parameters used in optional debug trace.
static void llcrypto_cipher_debug_print_hex(const char *name, void *p, int len) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("\t\t%s = ", name);
	for (int i = 0; i < len; i++) {
		LLCRYPTO_CIPHER_DEBUG_TRACE("%02X", ((uint8_t *)p)[i]);
	}
	LLCRYPTO_CIPHER_DEBUG_TRACE("\n");
}

static int LLCRYPTO_CIPHER_aes_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                    uint8_t *iv, int32_t iv_length, int32_t tag_length);
#ifndef NO_DES3
static int LLCRYPTO_CIPHER_des3cbc_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting,
                                        int32_t key_id,
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
 * @brief Loads a key held in RAM into the wolfCrypt AES context of a cipher.
 *
 * AES/GCM derives its hash subkey from the forward cipher, so its key goes through wc_AesGcmSetKey whatever the
 * direction. wc_AesSetKey does not compute that subkey (the tag is wrong) and gives a decrypt cipher the inverse
 * round keys (the decrypt fails). AES/CCM does not come here: it has its own init.
 *
 * @param[in]  cipher_ctx  Pointer to the cipher context, its transformation already set.
 * @param[in]  secret_key  Pointer to the key, its bytes in RAM.
 * @param[in]  iv  Pointer to the initialization vector, for the modes that take it at key setup.
 * @param[in]  is_decrypting  Cipher direction : '1' for decrypting, '0' for encrypting.
 *
 * @return The wolfCrypt return code, LLCRYPTO_WOLFCRYPT_SUCCESS when the key is set.
 */
static int llcrypto_aes_set_raw_key(LLCRYPTO_CIPHER_ctx *cipher_ctx, const LLCRYPTO_secret_key *secret_key,
                                    const uint8_t *iv, uint8_t is_decrypting) {
	int wolfcrypt_rc;
	Aes *aes = &cipher_ctx->wolfcrypt_ctx.aes_ctx;

	if (GCM_MODE == cipher_ctx->transformation->description.cipher_mode) {
#ifdef HAVE_AESGCM
		wolfcrypt_rc = wc_AesGcmSetKey(aes, secret_key->key, secret_key->key_length);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			LLCRYPTO_CIPHER_DEBUG_TRACE("wc_AesGcmSetKey() => %s\n", llcrypto_wc_error_message(wolfcrypt_rc));
		}
#else
		/* Unreachable: no GCM transformation is registered without HAVE_AESGCM. */
		wolfcrypt_rc = BAD_FUNC_ARG;
#endif // HAVE_AESGCM
	} else {
		int dir = ((uint8_t)0 != is_decrypting) ? AES_DECRYPTION : AES_ENCRYPTION;
		wolfcrypt_rc = wc_AesSetKey(aes, secret_key->key, secret_key->key_length, iv, dir);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			LLCRYPTO_CIPHER_DEBUG_TRACE("wc_AesSetKey() => %s\n", llcrypto_wc_error_message(wolfcrypt_rc));
		}
	}
	return wolfcrypt_rc;
}

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
 * @return LLCRYPTO_SUCCESS if the creation is successful,  LLCRYPTO_ERROR otherwise.
 *
 */
static int LLCRYPTO_CIPHER_aes_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting, int32_t key_id,
                                    uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s \n", __func__);

	LLCRYPTO_CIPHER_ctx *cipher_ctx;
	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();
	LLCRYPTO_key *key = (LLCRYPTO_key *)key_id;
	const LLCRYPTO_secret_key *secret_key = (const LLCRYPTO_secret_key *)key->secret_key;

	cipher_ctx = (LLCRYPTO_CIPHER_ctx *)llcrypto_calloc(1, (int32_t)sizeof(LLCRYPTO_CIPHER_ctx) - 1 + AES_BLOCK_SIZE);
	if (NULL == cipher_ctx) {
		return_code = LLCRYPTO_ERROR_OOM;
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		cipher_ctx->transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
		cipher_ctx->transformation->set_iv((void *)cipher_ctx, iv, iv_length);
		cipher_ctx->tag_length = tag_length;
		cipher_ctx->aad_length = 0;
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		if (NULL != secret_key->key) {
			/* Raw-bytes path: key material is in RAM. */
			wolfcrypt_rc = wc_AesInit(&cipher_ctx->wolfcrypt_ctx.aes_ctx, pHint, INVALID_DEVID);
			if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
				return_code = LLCRYPTO_ERROR;
				LLCRYPTO_CIPHER_DEBUG_TRACE("wc_AesInit() => %s\n", llcrypto_wc_error_message(wolfcrypt_rc));
			}

			if (LLCRYPTO_SUCCESS == return_code) {
				wolfcrypt_rc = llcrypto_aes_set_raw_key(cipher_ctx, secret_key, iv, is_decrypting);
				if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
					return_code = LLCRYPTO_ERROR;
				}
			}
		} else {
#ifdef WOLF_PRIVATE_KEY_ID
			/* PKCS#11 label-based path: key material stays in hardware. */
			wolfcrypt_rc = wc_AesInit_Label(&cipher_ctx->wolfcrypt_ctx.aes_ctx, secret_key->label, pHint,
			                                (int)secret_key->devId);
			if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
				return_code = LLCRYPTO_ERROR;
				LLCRYPTO_CIPHER_DEBUG_TRACE("wc_AesInit_Label() => %s\n", llcrypto_wc_error_message(wolfcrypt_rc));
			}

			if (LLCRYPTO_SUCCESS == return_code) {
				wolfcrypt_rc = wc_AesSetIV(&cipher_ctx->wolfcrypt_ctx.aes_ctx, iv);
				if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
					return_code = LLCRYPTO_ERROR;
					LLCRYPTO_CIPHER_DEBUG_TRACE("wc_AesSetIV() => %s\n", llcrypto_wc_error_message(wolfcrypt_rc));
				}
			}
#else
			/* No key bytes and no PKCS#11 support: the key cannot be used by this cipher. */
			return_code = LLCRYPTO_ERROR_INVALID_PARAMETER;
			LLCRYPTO_CIPHER_DEBUG_TRACE("Key material is not available and PKCS#11 support is disabled\n");
#endif // WOLF_PRIVATE_KEY_ID
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		*native_id = cipher_ctx;
	} else {
		if (NULL != cipher_ctx) {
			wc_AesFree(&cipher_ctx->wolfcrypt_ctx.aes_ctx);
			llcrypto_free(cipher_ctx);
		}
	}
	return return_code;
}

#ifdef WOLFSSL_AES_COUNTER
static int LLCRYPTO_CIPHER_aes_ctr_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting,
                                        int32_t key_id,
                                        uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLCRYPTO_UNUSED_PARAM(is_decrypting);
	return LLCRYPTO_CIPHER_aes_init(transformation_id, native_id, 0, key_id, iv, iv_length, tag_length); // in CTR mode,
	                                                                                                     // always
	                                                                                                     // configure
	                                                                                                     // for
	                                                                                                     // encryption
}

#endif // WOLFSSL_AES_COUNTER
#ifdef HAVE_AESCCM
static int LLCRYPTO_CIPHER_aes_ccm_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting,
                                        int32_t key_id,
                                        uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(is_decrypting);

	LLCRYPTO_CIPHER_ctx *cipher_ctx;
	int32_t return_code = LLCRYPTO_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();
	LLCRYPTO_key *key = (LLCRYPTO_key *)key_id;
	LLCRYPTO_secret_key *secret_key = (LLCRYPTO_secret_key *)key->secret_key;

	cipher_ctx = (LLCRYPTO_CIPHER_ctx *)llcrypto_calloc(1, (int32_t)sizeof(LLCRYPTO_CIPHER_ctx) - 1 + AES_BLOCK_SIZE);
	if (NULL == cipher_ctx) {
		return_code = LLCRYPTO_ERROR_OOM;
		LLCRYPTO_CIPHER_DEBUG_TRACE("Could not allocate memory for cipher_ctx\n");
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		int wolfcrypt_rc;
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		cipher_ctx->transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
		cipher_ctx->transformation->set_iv((void *)cipher_ctx, iv, iv_length);
		cipher_ctx->tag_length = tag_length;
		cipher_ctx->aad_length = 0;

		if (NULL != secret_key->key) {
			/* Raw-bytes path: key material is in RAM. */
			wolfcrypt_rc = wc_AesInit(&cipher_ctx->wolfcrypt_ctx.aes_ctx, pHint, INVALID_DEVID);
			if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
				return_code = (BAD_FUNC_ARG ==
				               wolfcrypt_rc) ? (int32_t)LLCRYPTO_ERROR_INVALID_PARAMETER : (int32_t)LLCRYPTO_ERROR;
				LLCRYPTO_CIPHER_DEBUG_TRACE("wc_AesInit() => %s\n", llcrypto_wc_error_message(wolfcrypt_rc));
			}

			if (LLCRYPTO_SUCCESS == return_code) {
				wolfcrypt_rc = wc_AesCcmSetKey(&cipher_ctx->wolfcrypt_ctx.aes_ctx, secret_key->key,
				                               secret_key->key_length);
				if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
					return_code = (BAD_FUNC_ARG ==
					               wolfcrypt_rc) ? (int32_t)LLCRYPTO_ERROR_INVALID_PARAMETER : (int32_t)LLCRYPTO_ERROR;
					LLCRYPTO_CIPHER_DEBUG_TRACE("wc_AesCcmSetKey() => %s\n", llcrypto_wc_error_message(wolfcrypt_rc));
				}
			}
		} else {
#ifdef WOLF_PRIVATE_KEY_ID
			/* PKCS#11 label-based path: key material stays in hardware.
			 * The nonce is supplied per encrypt/decrypt call - no wc_AesCcmSetKey needed. */
			wolfcrypt_rc = wc_AesInit_Label(&cipher_ctx->wolfcrypt_ctx.aes_ctx, secret_key->label, pHint,
			                                (int)secret_key->devId);
			if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
				return_code = (BAD_FUNC_ARG ==
				               wolfcrypt_rc) ? (int32_t)LLCRYPTO_ERROR_INVALID_PARAMETER : (int32_t)LLCRYPTO_ERROR;
				LLCRYPTO_CIPHER_DEBUG_TRACE("wc_AesInit_Label() => %s\n", llcrypto_wc_error_message(wolfcrypt_rc));
			}
#else
			/* No key bytes and no PKCS#11 support: the key cannot be used by this cipher. */
			return_code = (int32_t)LLCRYPTO_ERROR_INVALID_PARAMETER;
			LLCRYPTO_CIPHER_DEBUG_TRACE("Key material is not available and PKCS#11 support is disabled\n");
#endif // WOLF_PRIVATE_KEY_ID
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		*native_id = cipher_ctx;
	} else {
		if (NULL != cipher_ctx) {
			wc_AesFree(&cipher_ctx->wolfcrypt_ctx.aes_ctx);
			llcrypto_free(cipher_ctx);
		}
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
 * @return LLCRYPTO_SUCCESS if the creation is successful,  LLCRYPTO_ERROR otherwise.
 *
 */
static int LLCRYPTO_CIPHER_des3cbc_init(int32_t transformation_id, void **native_id, uint8_t is_decrypting,
                                        int32_t key_id,
                                        uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s %d\n", __func__, is_decrypting);

	LLCRYPTO_CIPHER_ctx *cipher_ctx;
	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();
	LLCRYPTO_key *key = (LLCRYPTO_key *)key_id;
	LLCRYPTO_secret_key *secret_key = (LLCRYPTO_secret_key *)key->secret_key;

	cipher_ctx = llcrypto_calloc(1, (int32_t)sizeof(LLCRYPTO_CIPHER_ctx) - 1 + DES_CBC_IV_SIZE);
	if (NULL == cipher_ctx) {
		return_code = LLCRYPTO_ERROR_OOM;
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		cipher_ctx->transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
		cipher_ctx->transformation->set_iv((void *)cipher_ctx, iv, iv_length);
		cipher_ctx->tag_length = tag_length;
		cipher_ctx->aad_length = 0;

		wc_Des3Init(&cipher_ctx->wolfcrypt_ctx.des3_ctx, pHint, INVALID_DEVID);

		if ((uint8_t)0 != is_decrypting) {
			wolfcrypt_rc = wc_Des3_SetKey(&cipher_ctx->wolfcrypt_ctx.des3_ctx, secret_key->key, iv, DES_DECRYPTION);
			LLCRYPTO_CIPHER_DEBUG_TRACE("%s mbedtls_des3_set3key_dec (rc = %d)\n", __func__, wolfcrypt_rc);
		} else {
			wolfcrypt_rc = wc_Des3_SetKey(&cipher_ctx->wolfcrypt_ctx.des3_ctx, secret_key->key, iv, DES_ENCRYPTION);
			LLCRYPTO_CIPHER_DEBUG_TRACE("%s mbedtls_des3_set3key_enc (rc = %d)\n", __func__, wolfcrypt_rc);
		}

		if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		*native_id = cipher_ctx;
	} else {
		if (NULL != cipher_ctx) {
			wc_Des3Free(&cipher_ctx->wolfcrypt_ctx.des3_ctx);
			llcrypto_free(cipher_ctx);
		}
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
 * @return LLCRYPTO_SUCCESS if the creation is successful,  LLCRYPTO_ERROR otherwise.
 *
 */
static int wolfcrypt_aes_cbc_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                            uint8_t doFinal) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s \n", __func__);

	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	LLCRYPTO_UNUSED_PARAM(doFinal);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_AesCbcDecrypt(&cipher_ctx->wolfcrypt_ctx.aes_ctx, output, buffer, buffer_length);
	if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLCRYPTO_ERROR;
	}

	return return_code;
}

#ifdef HAVE_AESCCM
static int wolfcrypt_aes_ccm_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                     uint8_t doFinal) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s \n", __func__);
	LLCRYPTO_UNUSED_PARAM(doFinal);

	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

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
	LLCRYPTO_CIPHER_DEBUG_TRACE("\twc_AesCcmDecrypt(%p, %p, %p, %d, %p, %d, %p, %d, %p, %d) => %s\n",
	                            aes, plaintext, ciphertext, ciphertext_len, iv, iv_len, tag, tag_len, aad, aad_len,
	                            llcrypto_wc_error_message(wolfcrypt_rc));
	llcrypto_cipher_debug_print_hex("[in] ciphertext", ciphertext, ciphertext_len);
	llcrypto_cipher_debug_print_hex("[in] iv        ", iv, iv_len);
	llcrypto_cipher_debug_print_hex("[in] tag       ", tag, tag_len);
	llcrypto_cipher_debug_print_hex("[in] aad       ", aad, aad_len);
	llcrypto_cipher_debug_print_hex("[out] plaintext", plaintext, ciphertext_len);
	if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		/* An authentication failure has its own code: the Crypto library raises AEADBadTagException on it. */
		if (AES_CCM_AUTH_E == wolfcrypt_rc) {
			return_code = LLCRYPTO_ERROR_AEAD_AUTH;
		} else {
			return_code = LLCRYPTO_ERROR;
		}
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
 * @return LLCRYPTO_SUCCESS if the creation is successful,  LLCRYPTO_ERROR otherwise.
 *
 */
static int wolfcrypt_des3_cipher_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                         uint8_t doFinal) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s \n", __func__);

	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	LLCRYPTO_UNUSED_PARAM(doFinal);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_Des3_CbcDecrypt(&cipher_ctx->wolfcrypt_ctx.des3_ctx, output, buffer, buffer_length);

	if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLCRYPTO_ERROR;
	}
	return return_code;
}

#endif // NO_DES3

#ifdef HAVE_AESGCM
static int wolfcrypt_aes_gcm_decrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                     uint8_t doFinal) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLCRYPTO_UNUSED_PARAM(doFinal);

	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

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
	LLCRYPTO_CIPHER_DEBUG_TRACE("\twc_AesGcmDecrypt(%p, %p, %p, %d, %p, %d, %p, %d, %p, %d) => %s\n",
	                            aes, plaintext, ciphertext, ciphertext_len, iv, iv_len, tag, tag_len, aad, aad_len,
	                            llcrypto_wc_error_message(wolfcrypt_rc));
	llcrypto_cipher_debug_print_hex("[in] ciphertext", ciphertext, ciphertext_len);
	llcrypto_cipher_debug_print_hex("[in] iv        ", iv, iv_len);
	llcrypto_cipher_debug_print_hex("[in] tag       ", tag, tag_len);
	llcrypto_cipher_debug_print_hex("[in] aad       ", aad, aad_len);
	llcrypto_cipher_debug_print_hex("[out] plaintext", plaintext, ciphertext_len);
	if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		/* An authentication failure has its own code: the Crypto library raises AEADBadTagException on it. */
		if (AES_GCM_AUTH_E == wolfcrypt_rc) {
			return_code = LLCRYPTO_ERROR_AEAD_AUTH;
		} else {
			return_code = LLCRYPTO_ERROR;
		}
	}

	return return_code;
}

#endif // HAVE_AESGCM

#ifdef HAVE_AES_CBC
static int wolfcrypt_aes_cbc_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                            uint8_t doFinal) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	LLCRYPTO_UNUSED_PARAM(doFinal);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_AesCbcEncrypt(&cipher_ctx->wolfcrypt_ctx.aes_ctx, output, buffer, buffer_length);

	if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLCRYPTO_ERROR;
	}

	return return_code;
}

#endif // HAVE_AES_CBC
#ifdef HAVE_AESCCM
static int wolfcrypt_aes_ccm_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                     uint8_t doFinal) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLCRYPTO_UNUSED_PARAM(doFinal);

	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

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
	LLCRYPTO_CIPHER_DEBUG_TRACE("\twc_AesCcmEncrypt(%p, %p, %p, %d, %p, %d, %p, %d, %p, %d) => %s\n",
	                            aes, ciphertext, plaintext, plaintext_len, iv, iv_len, tag, tag_len, aad, aad_len,
	                            llcrypto_wc_error_message(wolfcrypt_rc));
	llcrypto_cipher_debug_print_hex("[in] plaintext  ", plaintext, plaintext_len);
	llcrypto_cipher_debug_print_hex("[in] iv         ", iv, iv_len);
	llcrypto_cipher_debug_print_hex("[in] aad        ", aad, aad_len);
	llcrypto_cipher_debug_print_hex("[out] ciphertext", ciphertext, plaintext_len);
	llcrypto_cipher_debug_print_hex("[out] tag       ", tag, tag_len);
	if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLCRYPTO_ERROR;
	}

	return return_code;
}

#endif // HAVE_AESCCM
#ifdef WOLFSSL_AES_COUNTER
static int wolfcrypt_aes_ctr_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                     uint8_t doFinal) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	LLCRYPTO_UNUSED_PARAM(doFinal);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_AesCtrEncrypt(&cipher_ctx->wolfcrypt_ctx.aes_ctx, output, buffer, buffer_length);
	if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLCRYPTO_ERROR;
		LLCRYPTO_CIPHER_DEBUG_TRACE("wc_AesCtrEncrypt() failed with error %d\n", wolfcrypt_rc);
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
 * @return LLCRYPTO_SUCCESS if the creation is successful,  LLCRYPTO_ERROR otherwise.
 *
 */
static int wolfcrypt_des3_cipher_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                         uint8_t doFinal) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLCRYPTO_UNUSED_PARAM(doFinal);

	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

	wolfcrypt_rc = wc_Des3_CbcEncrypt(&cipher_ctx->wolfcrypt_ctx.des3_ctx, output, buffer, buffer_length);

	if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLCRYPTO_ERROR;
	}

	return return_code;
}

#endif // NO_DES3
#ifdef HAVE_AESGCM
static int wolfcrypt_aes_gcm_encrypt(void *native_id, uint8_t *buffer, int32_t buffer_length, uint8_t *output,
                                     uint8_t doFinal) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLCRYPTO_UNUSED_PARAM(doFinal);

	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

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
	LLCRYPTO_CIPHER_DEBUG_TRACE("\twc_AesGcmEncrypt(%p, %p, %p, %d, %p, %d, %p, %d, %p, %d) => %s\n",
	                            aes, ciphertext, plaintext, plaintext_len, iv, iv_len, tag, tag_len, aad, aad_len,
	                            llcrypto_wc_error_message(wolfcrypt_rc));
	llcrypto_cipher_debug_print_hex("[in] plaintext  ", plaintext, plaintext_len);
	llcrypto_cipher_debug_print_hex("[in] iv         ", iv, iv_len);
	llcrypto_cipher_debug_print_hex("[in] aad        ", aad, aad_len);
	llcrypto_cipher_debug_print_hex("[out] ciphertext", ciphertext, plaintext_len);
	llcrypto_cipher_debug_print_hex("[out] tag       ", tag, tag_len);
	if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
		return_code = LLCRYPTO_ERROR;
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
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;
	cipher_ctx->iv_length = iv_length; // at this point, we know iv_length < MAX_IV_LENGTH
	llcrypto_memcpy(cipher_ctx->iv, iv, iv_length);
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
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;
	cipher_ctx->iv_length = iv_length;
	llcrypto_memcpy(cipher_ctx->iv, iv, cipher_ctx->iv_length);
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
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s native_id %p\n", __func__, native_id);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;
	wc_AesFree(&cipher_ctx->wolfcrypt_ctx.aes_ctx);
	llcrypto_free(native_id);
}

#ifndef NO_DES3
/**
 * @brief Frees the resources and context associated of an Wolfcrypt DES key structure.
 *
 * @param[in]  native_id Pointer to a Wolfcrypt DES key structure.
 *
 */
static void wolfcrypt_des3_cipher_close(void *native_id) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s native_id %p\n", __func__, native_id);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;
	wc_Des3Free(&cipher_ctx->wolfcrypt_ctx.des3_ctx);
	llcrypto_free(native_id);
}

#endif // NO_DES3

// --------------------------------------------------------------------------------
// LLCRYPTO_CIPHER_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLCRYPTO_CIPHER_IMPL_get_transformation_description(uint8_t *transformation_name,
                                                            LLCRYPTO_CIPHER_transformation_desc *transformation_desc) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s(transf=\"%s\")\n", __func__, transformation_name);

	static LLCRYPTO_CIPHER_transformation available_transformations[] = {
#ifdef HAVE_AES_CBC
		{
			.name = "AES/CBC/NoPadding",
			.init = LLCRYPTO_CIPHER_aes_init,
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
			.init = LLCRYPTO_CIPHER_aes_ccm_init, // always configure for encryption regardless of is_decrypting
			                                      // parameter
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
			.init = LLCRYPTO_CIPHER_aes_ctr_init,     // always configure for encryption regardless of is_decrypting
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
			.init = LLCRYPTO_CIPHER_des3cbc_init,
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
			.init = LLCRYPTO_CIPHER_aes_init,
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

	int32_t return_code = LLCRYPTO_SUCCESS;
	int32_t nb_transformations = sizeof(available_transformations) / sizeof(LLCRYPTO_CIPHER_transformation);
	LLCRYPTO_CIPHER_transformation *transformation = &available_transformations[0];

	while (--nb_transformations >= 0) {
		if (strcmp((const char *)transformation_name, transformation->name) == 0) {
			llcrypto_memcpy(transformation_desc, &(transformation->description),
			                sizeof(LLCRYPTO_CIPHER_transformation_desc));
			break;
		}
		transformation++;
	}

	if (nb_transformations >= 0) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		return_code = (int32_t)transformation;
	} else {
		return_code = LLCRYPTO_ERROR;
	}
	return return_code;
}

/*
 * A Cipher whose init failed keeps the Java-side native ID at -1: the Crypto library assigns it only on success,
 * and its update/doFinal path passes the field down without checking it. Casting that value to a context pointer
 * and dereferencing it faults the Core Engine, so every entry point taking a native ID refuses an uninitialized one
 * and throws instead.
 */
#define LLCRYPTO_CIPHER_NO_NATIVE_ID (-1)

/**
 * @brief Checks that a native ID designates an initialized cipher context.
 *
 * @param[in] native_id Native ID received from the Java side.
 *
 * @return true when the native ID is valid, false when it is not (an exception is then thrown).
 */
static bool llcrypto_cipher_check_native_id(int32_t native_id) {
	bool valid = (LLCRYPTO_CIPHER_NO_NATIVE_ID != native_id) && (0 != native_id);
	if (!valid) {
		llcrypto_throw(LLCRYPTO_ERROR, "Cipher is not initialized");
	}
	return valid;
}

// See the header file for the function documentation
int32_t LLCRYPTO_CIPHER_IMPL_get_buffered_length(int32_t nativeTransformationId, int32_t nativeId) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLCRYPTO_UNUSED_PARAM(nativeTransformationId);
	LLCRYPTO_UNUSED_PARAM(nativeId);
	return LLCRYPTO_SUCCESS;
}

// See the header file for the function documentation
void LLCRYPTO_CIPHER_IMPL_get_IV(int32_t transformation_id, int32_t native_id, uint8_t *iv, int32_t iv_length) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	if (llcrypto_cipher_check_native_id(native_id)) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		const LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;
		llcrypto_memcpy(iv, cipher_ctx->iv, iv_length);
	}
}

// See the header file for the function documentation
void LLCRYPTO_CIPHER_IMPL_set_IV(int32_t transformation_id, int32_t native_id, uint8_t *iv, int32_t iv_length) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s(cipher=%p, iv=%p)", __func__, (void *)native_id, iv);
	for (int i = 0; i < iv_length; i++) {
		LLCRYPTO_CIPHER_DEBUG_TRACE("%02X", iv[i]);
	}
	LLCRYPTO_CIPHER_DEBUG_TRACE(")\n");
	if (iv_length > LLCRYPTO_CIPHER_MAX_IV_LENGTH) {
		llcrypto_throw(LLCRYPTO_ERROR, "Max IV length exceeded");
	} else if (llcrypto_cipher_check_native_id(native_id)) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		transformation->set_iv((void *)native_id, iv, iv_length);
	} else {
		/* Invalid native ID: the check has already thrown the exception. */
	}
}

// See the header file for the function documentation
int32_t LLCRYPTO_CIPHER_IMPL_get_IV_length(int32_t transformation_id, int32_t native_id) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	int32_t iv_length = LLCRYPTO_ERROR;
	if (llcrypto_cipher_check_native_id(native_id)) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		const LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;
		iv_length = cipher_ctx->iv_length;
	}
	return iv_length;
}

// See the header file for the function documentation
void LLCRYPTO_CIPHER_IMPL_update_AAD(int32_t transformation_id, int32_t native_id, uint8_t *aad, int32_t offset,
                                     int32_t aad_length) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	if (llcrypto_cipher_check_native_id(native_id)) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLCRYPTO_CIPHER_ctx *cipher_ctx = (LLCRYPTO_CIPHER_ctx *)native_id;

		if (aad_length > LLCRYPTO_CIPHER_MAX_AAD_LENGTH) {
			LLCRYPTO_CIPHER_DEBUG_TRACE("Invalid AAD length, actual: %d ; max: %d \n", aad_length,
			                            LLCRYPTO_CIPHER_MAX_AAD_LENGTH);
			llcrypto_throw(LLCRYPTO_ERROR_INVALID_PARAMETER, "Invalid AAD length");
		} else {
			cipher_ctx->aad_length = aad_length;
			llcrypto_memcpy(cipher_ctx->aad, &aad[offset], aad_length);
		}
	}
}

// See the header file for the function documentation
int32_t LLCRYPTO_CIPHER_IMPL_init(int32_t transformation_id, uint8_t is_decrypting, int32_t key,
                                  uint8_t *iv, int32_t iv_length, int32_t tag_length) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);

	int32_t return_code = LLCRYPTO_SUCCESS;
	void *native_id = NULL;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;

	LLCRYPTO_CIPHER_DEBUG_TRACE("transf=\"%s\", ", transformation->name);
	LLCRYPTO_CIPHER_DEBUG_TRACE("mode=\"%s\", ", is_decrypting ? "DECRYPT" : "ENCRYPT");
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_CIPHER_DEBUG_TRACE("key=%p,", (void *)key);
	LLCRYPTO_CIPHER_DEBUG_TRACE("iv=");
	for (int i = 0; i < iv_length; i++) {
		LLCRYPTO_CIPHER_DEBUG_TRACE("%02X", iv[i]);
	}
	LLCRYPTO_CIPHER_DEBUG_TRACE(", tag_length=%d", tag_length);
	LLCRYPTO_CIPHER_DEBUG_TRACE(")\n");

	if ((iv_length <= 0) || (iv_length > LLCRYPTO_CIPHER_MAX_IV_LENGTH)) {
		llcrypto_throw(iv_length, "Invalid IV length");
		return_code = LLCRYPTO_ERROR;
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		if (tag_length > LLCRYPTO_CIPHER_MAX_TAG_LENGTH) {
			llcrypto_throw(tag_length, "Invalid tag length");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		return_code = transformation->init(transformation_id, &native_id, is_decrypting, key, iv, iv_length,
		                                   tag_length);
		if ((LLCRYPTO_SUCCESS != return_code) && (LLCRYPTO_ERROR_OOM != return_code)
		    && (LLCRYPTO_ERROR_INVALID_PARAMETER != return_code)) {
			/* Surface the failure as a native exception, except for the two codes the LLAPI contract defines as
			 * returned. LLCRYPTO_ERROR_OOM is returned so the Crypto library can run a garbage collection and retry.
			 * LLCRYPTO_ERROR_INVALID_PARAMETER is returned so the refusal reaches the application as the checked
			 * exception Cipher.init() declares rather than as an unchecked native exception. */
			llcrypto_throw(return_code, "LLCRYPTO_CIPHER_IMPL_init failed");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		// register SNI native resource
		if (SNI_OK != SNI_registerResource(native_id, transformation->close, NULL)) {
			llcrypto_throw(LLCRYPTO_ERROR, "Can't register SNI native resource");
			transformation->close((void *)native_id);
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.6]: Abstract data type for SNI usage
		return_code = (int32_t)(native_id);
		LLCRYPTO_CIPHER_DEBUG_TRACE("%s() => %p\n", __func__, native_id);
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_CIPHER_IMPL_decrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                     int32_t buffer_offset,
                                     int32_t buffer_length, uint8_t *output, int32_t output_offset, uint8_t doFinal) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s(cipher=%p, inBuf=%p, inOff=%d, inLen=%d, outBuf=%p, outOff=%d, doFinal=%s)\n",
	                            __func__, (void *)native_id, buffer, buffer_offset, buffer_length, output,
	                            output_offset,
	                            (doFinal == 0u) ? "false" : "true");

	int32_t return_code = LLCRYPTO_ERROR;
	if (llcrypto_cipher_check_native_id(native_id)) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		int rc = transformation->decrypt((void *)native_id, &buffer[buffer_offset], buffer_length,
		                                 &output[output_offset], doFinal);
		if (LLCRYPTO_ERROR_AEAD_AUTH == rc) {
			/* Returned, not thrown: the Crypto library turns this code into AEADBadTagException. */
			return_code = LLCRYPTO_ERROR_AEAD_AUTH;
		} else if (LLCRYPTO_SUCCESS != rc) {
			llcrypto_throw(rc, "LLCRYPTO_CIPHER_IMPL_decrypt failed");
		} else {
			return_code = SNI_getArrayLength(output); // if AEAD, output is smaller than input (smaller by tag
			                                          // length), otherwise, should be equal to buffer_length (input);
		}
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_CIPHER_IMPL_encrypt(int32_t transformation_id, int32_t native_id, uint8_t *buffer,
                                     int32_t buffer_offset,
                                     int32_t buffer_length, uint8_t *output, int32_t output_offset, uint8_t doFinal) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s(cipher=%p, inBuf=%p, inOff=%d, inLen=%d, outBuf=%p, outOff=%d, doFinal=%s)\n",
	                            __func__, (void *)native_id, buffer, buffer_offset, buffer_length, output,
	                            output_offset,
	                            (doFinal == 0u) ? "false" : "true");
	int32_t return_code = LLCRYPTO_ERROR;
	if (llcrypto_cipher_check_native_id(native_id)) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		int rc = transformation->encrypt((void *)native_id, &buffer[buffer_offset], buffer_length,
		                                 &output[output_offset], doFinal);
		if (LLCRYPTO_SUCCESS != rc) {
			llcrypto_throw(rc, "LLCRYPTO_CIPHER_IMPL_encrypt failed");
		} else {
			return_code = SNI_getArrayLength(output); // if AEAD, should include tag, otherwise, should be equal to
			                                          // buffer_length (input)
		}
	}
	return return_code;
}

// See the header file for the function documentation
void LLCRYPTO_CIPHER_IMPL_close(int32_t transformation_id, int32_t native_id) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;

	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	transformation->close((void *)native_id);
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	if (SNI_OK != SNI_unregisterResource((void *)native_id, (SNI_closeFunction)transformation->close)) {
		llcrypto_throw(LLCRYPTO_ERROR, "Can't unregister SNI native resource");
	}
}

// See the header file for the function documentation
int32_t LLCRYPTO_CIPHER_IMPL_get_close_id(int32_t transformation_id) {
	LLCRYPTO_CIPHER_DEBUG_TRACE("%s()\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_CIPHER_transformation *transformation = (LLCRYPTO_CIPHER_transformation *)transformation_id;
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)transformation->close;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
