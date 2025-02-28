/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Digest.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_DIGEST_impl.h>
#include <LLSEC_ERRORS.h>
#include <LLSEC_wolfcrypt.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>

// --------------------------------------------------------------------------------
// Macros and Defines
// --------------------------------------------------------------------------------

#define MD5_DIGEST_LENGTH     WC_MD5_DIGEST_SIZE
#define SHA1_DIGEST_LENGTH    WC_SHA_DIGEST_SIZE
#define SHA256_DIGEST_LENGTH  WC_SHA256_DIGEST_SIZE
#define SHA512_DIGEST_LENGTH  WC_SHA512_DIGEST_SIZE

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef int (*LLSEC_DIGEST_init)(void **native_id);
typedef int (*LLSEC_DIGEST_update)(void *native_id, uint8_t *buffer, int32_t buffer_length);
typedef int (*LLSEC_DIGEST_digest)(void *native_id, uint8_t *out, int32_t *out_length);
typedef void (*LLSEC_DIGEST_close)(void *native_id);

/*
 * LL-API related functions & struct
 */
typedef struct {
	char *name;
	LLSEC_DIGEST_init init;
	LLSEC_DIGEST_update update;
	LLSEC_DIGEST_digest digest;
	LLSEC_DIGEST_close close;
	LLSEC_DIGEST_algorithm_desc description;
} LLSEC_DIGEST_algorithm;

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static int LLSEC_DIGEST_MD5_init(void **native_id);
static int LLSEC_DIGEST_SHA1_init(void **native_id);
static int LLSEC_DIGEST_SHA256_init(void **native_id);
static int LLSEC_DIGEST_SHA512_init(void **native_id);
static int LLSEC_DIGEST_MD5_update(void *native_id, uint8_t *buffer, int32_t buffer_length);
static int LLSEC_DIGEST_SHA1_update(void *native_id, uint8_t *buffer, int32_t buffer_length);
static int LLSEC_DIGEST_SHA256_update(void *native_id, uint8_t *buffer, int32_t buffer_length);
static int LLSEC_DIGEST_SHA512_update(void *native_id, uint8_t *buffer, int32_t buffer_length);
static int LLSEC_DIGEST_MD5_digest(void *native_id, uint8_t *out, int32_t *out_length);
static int LLSEC_DIGEST_SHA1_digest(void *native_id, uint8_t *out, int32_t *out_length);
static int LLSEC_DIGEST_SHA256_digest(void *native_id, uint8_t *out, int32_t *out_length);
static int LLSEC_DIGEST_SHA512_digest(void *native_id, uint8_t *out, int32_t *out_length);
static void LLSEC_DIGEST_MD5_close(void *native_id);
static void LLSEC_DIGEST_SHA1_close(void *native_id);
static void LLSEC_DIGEST_SHA256_close(void *native_id);
static void LLSEC_DIGEST_SHA512_close(void *native_id);

// cppcheck-suppress [misra-c2012-8.9] : Define here for code readability even if it called once in this file.
static LLSEC_DIGEST_algorithm available_digest_algorithms[] = {
#if WOLF_CONF_MD5 == 1
	{
		.name = "MD5",
		.init = LLSEC_DIGEST_MD5_init,
		.update = LLSEC_DIGEST_MD5_update,
		.digest = LLSEC_DIGEST_MD5_digest,
		.close = LLSEC_DIGEST_MD5_close,
		{
			.digest_length = MD5_DIGEST_LENGTH
		}
	},
#endif
#if WOLF_CONF_SHA1 == 1
	{
		.name = "SHA-1",
		.init = LLSEC_DIGEST_SHA1_init,
		.update = LLSEC_DIGEST_SHA1_update,
		.digest = LLSEC_DIGEST_SHA1_digest,
		.close = LLSEC_DIGEST_SHA1_close,
		{
			.digest_length = SHA1_DIGEST_LENGTH
		}
	},
#endif
#if WOLF_CONF_SHA2_256 == 1
	{
		.name = "SHA-256",
		.init = LLSEC_DIGEST_SHA256_init,
		.update = LLSEC_DIGEST_SHA256_update,
		.digest = LLSEC_DIGEST_SHA256_digest,
		.close = LLSEC_DIGEST_SHA256_close,
		{
			.digest_length = SHA256_DIGEST_LENGTH
		}
	},
#endif
#if WOLF_CONF_SHA2_512 == 1
	{
		.name = "SHA-512",
		.init = LLSEC_DIGEST_SHA512_init,
		.update = LLSEC_DIGEST_SHA512_update,
		.digest = LLSEC_DIGEST_SHA512_digest,
		.close = LLSEC_DIGEST_SHA512_close,
		{
			.digest_length = SHA512_DIGEST_LENGTH
		}
	}
#endif
};

// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
typedef union {
#if WOLF_CONF_MD5 == 1
	wc_Md5 md5_ctx;
#endif
#if WOLF_CONF_SHA1
	wc_Sha sha1_ctx;
#endif
#if WOLF_CONF_SHA2_256 == 1
	wc_Sha256 sha256_ctx;
#endif
#if WOLF_CONF_SHA2_512 == 1
	wc_Sha512 sha512_ctx;
#endif
} wolfcrypt_digest_context_t;

#if WOLF_CONF_MD5 == 1
/*
 * Specific md5 function
 */

/**
 * @brief Initializes the Wolfcrypt context to create the digest.
 *
 * @param[out] native_id        The pointer pointer to the native structure storing the MD5 context.
 *
 * @return LLSEC_SUCCESS if the initialization is successful, LLSEC_ERROR otherwise.
 *
 */
static int LLSEC_DIGEST_MD5_init(void **native_id) {
	int return_code = LLSEC_SUCCESS;
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = LLSEC_calloc(1, sizeof(wc_Md5));
	if (NULL == md_ctx) {
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		int wolfcrypt_rc = wc_InitMd5(&md_ctx->md5_ctx);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS != return_code) {
		wc_Md5Free(&md_ctx->md5_ctx);
		LLSEC_free(md_ctx);
	} else {
		*native_id = md_ctx;
	}

	return return_code;
}

/**
 * @brief Retrieves the digest and stores it in a buffer.
 *
 * @param[in] native_id        The pointer to the native structure storing the MD5 context.
 * @param[in] out       A pointer to the destination buffer.
 * @param[out] out_length  A pointer to a variable to store the number of bytes putted to the buffer.
 *
 * @return LLSEC_WOLFCRYPT_SUCCESS if recovery is successful, Wolfcrypt error code otherwise.
 *
 */
static int LLSEC_DIGEST_MD5_digest(void *native_id, uint8_t *out, int32_t *out_length) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;
	int wolfcrypt_rc = wc_Md5Final(&md_ctx->md5_ctx, out);

	if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
		*out_length = MD5_DIGEST_LENGTH;
	}

	return wolfcrypt_rc;
}

/**
 * @brief Updates the digest with the provided dataset.
 *
 * @param[in] native_id        The pointer pointer to the native structure storing the MD5 context.
 * @param[in] buffer    A pointer to the buffer containing the data set.
 * @param[in] buffer_length The size of the data set buffer.
 *
 * @return  LLSEC_WOLFCRYPT_SUCCESS if update is successful, Wolfcrypt error code otherwise.
 *
 */
static int LLSEC_DIGEST_MD5_update(void *native_id, uint8_t *buffer, int32_t buffer_length) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;
	int wolfcrypt_rc = wc_Md5Update(&md_ctx->md5_ctx, buffer, buffer_length);
	return wolfcrypt_rc;
}

/**
 * @brief Frees the Wolfcrypt resources and context associated with a digest.
 *
 * @param[in] native_id        The pointer pointer to the native structure storing the MD5 context.
 *
 *
 */
static void  LLSEC_DIGEST_MD5_close(void *native_id) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;

	/* Memory deallocation */
	wc_Md5Free(&md_ctx->md5_ctx);
	LLSEC_free(md_ctx);
}

#endif

/*
 * Specific sha-1 function
 */
#if WOLF_CONF_SHA1 == 1

/**
 * @brief Initializes the Wolfcrypt context to create the digest.
 *
 * @param[out] native_id        The pointer pointer to the native structure storing the SHA1 context.
 *
 * @return LLSEC_SUCCESS if the initialization is successful, LLSEC_ERROR otherwise.
 *
 */
static int LLSEC_DIGEST_SHA1_init(void **native_id) {
	int return_code = LLSEC_SUCCESS;
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = LLSEC_calloc(1, sizeof(wc_Sha));
	if (NULL == md_ctx) {
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		int wolfcrypt_rc = wc_InitSha(&md_ctx->sha1_ctx);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS != return_code) {
		wc_ShaFree(&md_ctx->sha1_ctx);
		LLSEC_free(md_ctx);
	} else {
		*native_id = md_ctx;
	}

	return return_code;
}

/**
 * @brief Retrieves the digest and stores it in a buffer.
 *
 * @param[in] native_id        The pointer to the native structure storing the SHA1 context.
 * @param[in] out       A pointer to the destination buffer.
 * @param[out] out_length  A pointer to a variable to store the number of bytes putted to the buffer.
 *
 * @return LLSEC_WOLFCRYPT_SUCCESS if recovery is successful, Wolfcrypt error code otherwise.
 *
 */
static int LLSEC_DIGEST_SHA1_digest(void *native_id, uint8_t *out, int32_t *out_length) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;
	int wolfcrypt_rc = wc_ShaFinal(&md_ctx->sha1_ctx, out);

	if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
		*out_length = SHA1_DIGEST_LENGTH;
	}

	return wolfcrypt_rc;
}

/**
 * @brief Updates the digest with the provided dataset.
 *
 * @param[in] native_id        The pointer to the native structure storing the SHA1 context.
 * @param[in] buffer    A pointer to the buffer containing the data set.
 * @param[in] buffer_length The size of the data set buffer.
 *
 * @return  LLSEC_WOLFCRYPT_SUCCESS if update is successful, Wolfcrypt error code otherwise.
 *
 */
static int LLSEC_DIGEST_SHA1_update(void *native_id, uint8_t *buffer, int32_t buffer_length) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;
	int wolfcrypt_rc = wc_ShaUpdate(&md_ctx->sha1_ctx, buffer, buffer_length);
	return wolfcrypt_rc;
}

/**
 * @brief Frees the Wolfcrypt resources and context associated with a digest.
 *
 * @param[in] native_id        The pointer to the native structure storing the SHA1 context.
 *
 */
static void  LLSEC_DIGEST_SHA1_close(void *native_id) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;

	/* Memory deallocation */
	wc_ShaFree(&md_ctx->sha1_ctx);
	LLSEC_free(md_ctx);
}

#endif

/*
 * Specific sha-256 function
 */
#if WOLF_CONF_SHA2_256 == 1

/**
 * @brief Initializes the Wolfcrypt context to create the digest.
 *
 * @param[out] native_id        The pointer of pointer to the native structure storing the SHA256 context.
 *
 * @return LLSEC_SUCCESS if the initialization is successful, LLSEC_ERROR otherwise.
 *
 */
static int LLSEC_DIGEST_SHA256_init(void **native_id) {
	int return_code = LLSEC_SUCCESS;
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = LLSEC_calloc(1, sizeof(wc_Sha256));
	if (NULL == md_ctx) {
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		int wolfcrypt_rc = wc_InitSha256(&md_ctx->sha256_ctx);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS != return_code) {
		wc_Sha256Free(&md_ctx->sha256_ctx);
		LLSEC_free(md_ctx);
	} else {
		*native_id = md_ctx;
	}

	return return_code;
}

/**
 * @brief Retrieves the digest and stores it in a buffer.
 *
 * @param[in] native_id        The pointer to the native structure storing the SHA256 context.
 * @param[in] out       A pointer to the destination buffer.
 * @param[out] out_length  A pointer to a variable to store the number of bytes putted to the buffer.
 *
 * @return LLSEC_WOLFCRYPT_SUCCESS if recovery is successful, Wolfcrypt error code otherwise.
 *
 */
static int LLSEC_DIGEST_SHA256_digest(void *native_id, uint8_t *out, int32_t *out_length) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;
	int wolfcrypt_rc = wc_Sha256Final(&md_ctx->sha256_ctx, out);

	if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
		*out_length = SHA256_DIGEST_LENGTH;
	}

	return wolfcrypt_rc;
}

/**
 * @brief Updates the digest with the provided dataset.
 *
 * @param[in] native_id        The pointer to the native structure storing the SHA256 context.
 * @param[in] buffer
 * @param[in] buffer_length
 *
 * @return The nativeId of the newly initialized resource.
 *
 */
static int LLSEC_DIGEST_SHA256_update(void *native_id, uint8_t *buffer, int32_t buffer_length) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;
	int wolfcrypt_rc = wc_Sha256Update(&md_ctx->sha256_ctx, buffer, buffer_length);
	return wolfcrypt_rc;
}

/**
 * @brief Frees the Wolfcrypt resources and context associated with a digest.
 *
 * @param[in] native_id        The pointer to the native structure storing the SHA256 context.
 *
 */
static void  LLSEC_DIGEST_SHA256_close(void *native_id) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;

	/* Memory deallocation */
	wc_Sha256Free(&md_ctx->sha256_ctx);
	LLSEC_free(md_ctx);
}

#endif
/*
 * Specific sha-512 function
 */
#if WOLF_CONF_SHA2_512 == 1
/**
 * @brief Initializes the Wolfcrypt context to create the digest.
 *
 * @param[out] native_id        The pointer of pointer to the native structure storing the SHA512 context.
 *
 * @return LLSEC_SUCCESS if the initialization is successful, LLSEC_ERROR otherwise.
 *
 */
static int LLSEC_DIGEST_SHA512_init(void **native_id) {
	int return_code = LLSEC_SUCCESS;
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = LLSEC_calloc(1, sizeof(wc_Sha512));
	if (NULL == md_ctx) {
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		int wolfcrypt_rc = wc_InitSha512(&md_ctx->sha512_ctx);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS != return_code) {
		wc_Sha512Free(&md_ctx->sha512_ctx);
		LLSEC_free(md_ctx);
	} else {
		*native_id = md_ctx;
	}

	return return_code;
}

/**
 * @brief Retrieves the digest and stores it in a buffer.
 *
 * @param[in] native_id        The pointer to the native structure storing the SHA512 context.
 * @param[in] out       A pointer to the destination buffer.
 * @param[out] out_length  A pointer to a variable to store the number of bytes putted to the buffer.
 *
 * @return LLSEC_WOLFCRYPT_SUCCESS if recovery is successful, Wolfcrypt error code otherwise.
 *
 */
static int LLSEC_DIGEST_SHA512_digest(void *native_id, uint8_t *out, int32_t *out_length) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;
	int wolfcrypt_rc = wc_Sha512Final(&md_ctx->sha512_ctx, out);

	if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
		*out_length = SHA512_DIGEST_LENGTH;
	}

	return wolfcrypt_rc;
}

/**
 * @brief Updates the digest with the provided dataset.
 *
 * @param[in] native_id        The pointer to the native structure storing the SHA512 context.
 * @param[in] buffer    A pointer to the buffer containing the data set.
 * @param[in] buffer_length The size of the data set buffer.
 *
 * @return  LLSEC_WOLFCRYPT_SUCCESS if update is successful, Wolfcrypt error code otherwise.
 *
 */
static int LLSEC_DIGEST_SHA512_update(void *native_id, uint8_t *buffer, int32_t buffer_length) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;
	int wolfcrypt_rc = wc_Sha512Update(&md_ctx->sha512_ctx, buffer, buffer_length);
	return wolfcrypt_rc;
}

/**
 * @brief Frees the Wolfcrypt resources and context associated with a digest.
 *
 * @param[in] native_id        The pointer to the native structure storing the SHA512 context.
 *
 */
static void  LLSEC_DIGEST_SHA512_close(void *native_id) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);

	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-19.2] : Abstract data type for SNI usage
	wolfcrypt_digest_context_t *md_ctx = (wolfcrypt_digest_context_t *)native_id;

	/* Memory deallocation */
	wc_Sha512Free(&md_ctx->sha512_ctx);
	LLSEC_free(md_ctx);
}

#endif

// --------------------------------------------------------------------------------
// LLSEC_DIGEST_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_DIGEST_IMPL_get_algorithm_description(uint8_t *algorithm_name,
                                                    LLSEC_DIGEST_algorithm_desc *algorithm_desc) {
	int32_t return_code = LLSEC_ERROR;
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);
	int32_t nb_algorithms = sizeof(available_digest_algorithms) / sizeof(LLSEC_DIGEST_algorithm);
	LLSEC_DIGEST_algorithm *algorithm = &available_digest_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, (algorithm->name))) {
			(void)memcpy(algorithm_desc, &(algorithm->description), sizeof(LLSEC_DIGEST_algorithm_desc));
			break;
		}
		algorithm++;
	}

	if (0 <= nb_algorithms) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		return_code = (int32_t)algorithm;
	}
	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_DIGEST_IMPL_init(int32_t algorithm_id) {
	int32_t return_code = LLSEC_SUCCESS;
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);
	void *native_id = NULL;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_DIGEST_algorithm *algorithm = (LLSEC_DIGEST_algorithm *)algorithm_id;

	return_code = algorithm->init((void **)&native_id);

	if (LLSEC_SUCCESS != return_code) {
		(void)SNI_throwNativeException(return_code, "LLSEC_DIGEST_IMPL_init failed");
	} else {
		/* register SNI native resource */
		if (SNI_OK != SNI_registerResource(native_id, algorithm->close, NULL)) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't register SNI native resource");
			algorithm->close((void *)native_id);
			return_code = LLSEC_ERROR;
		} else {
			// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
			return_code = (int32_t)native_id;
		}
	}
	return return_code;
}

// See the header file for the function documentation
void LLSEC_DIGEST_IMPL_close(int32_t algorithm_id, int32_t native_id) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_DIGEST_algorithm *algorithm = (LLSEC_DIGEST_algorithm *)algorithm_id;

	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	algorithm->close((void *)native_id);

	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	if (SNI_OK != SNI_unregisterResource((void *)native_id, (SNI_closeFunction)algorithm->close)) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "Can't unregister SNI native resource");
	}
}

// See the header file for the function documentation
void LLSEC_DIGEST_IMPL_update(int32_t algorithm_id, int32_t native_id, uint8_t *buffer, int32_t buffer_offset,
                              int32_t buffer_length) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_DIGEST_algorithm *algorithm = (LLSEC_DIGEST_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	int return_code = algorithm->update((void *)native_id, &buffer[buffer_offset], buffer_length);

	if (LLSEC_SUCCESS != return_code) {
		(void)SNI_throwNativeException(return_code, "LLSEC_DIGEST_IMPL_update failed");
	}
}

// See the header file for the function documentation
void LLSEC_DIGEST_IMPL_digest(int32_t algorithm_id, int32_t native_id, uint8_t *out, int32_t out_offset,
                              int32_t out_length) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_DIGEST_algorithm *algorithm = (LLSEC_DIGEST_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	int return_code = algorithm->digest((void *)native_id, &out[out_offset], &out_length);

	if (LLSEC_SUCCESS != return_code) {
		(void)SNI_throwNativeException(return_code, "LLSEC_DIGEST_IMPL_digest failed");
	}
}

// See the header file for the function documentation
int32_t LLSEC_DIGEST_IMPL_get_close_id(int32_t algorithm_id) {
	LLSEC_DIGEST_DEBUG_TRACE("%s \n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_DIGEST_algorithm *algorithm = (LLSEC_DIGEST_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)algorithm->close;
}
