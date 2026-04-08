/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Common functions implementation.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_wolfcrypt.h>
#include <LLSEC_impl.h>
#include <LLSEC_ERRORS.h>
#include <LLSEC_common.h>
#include <microej_async_worker.h>
#include "bsp_util.h"

#include <sni.h>
#include <stdint.h>

#if !defined(NO_ASN) && !defined(NO_ASN_TIME)
#include <microej.h>
#include <microej_time.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#endif

// --------------------------------------------------------------------------------
// Variable declarations
// --------------------------------------------------------------------------------

MICROEJ_ASYNC_WORKER_worker_declare(llsec_worker, LLSEC_WORKER_JOB_COUNT, LLSEC_worker_params_t,
                                    LLSEC_WAITING_LIST_SIZE);
OSAL_task_stack_declare(llsec_worker_stack, LLSEC_WORKER_STACK_SIZE);

WC_RNG *llsec_wolfcrypt_RNG;

// --------------------------------------------------------------------------------
// Wrapper functions
// --------------------------------------------------------------------------------

void llsec_memcpy(void *destination, const void *source, size_t num) {
	void *dest = memcpy(destination, source, num);
	LLSEC_GENERIC_DEBUG_TRACE("\tmemcpy(%p, %p, %d) = %p\n", destination, source, num, dest);
	// cppcheck-suppress misra-c2012-17.7 // Return value does not require checking.
	(void)dest;
}

void llsec_strncpy(uint8_t *destination, const char *source, size_t num) {
	size_t length = strlen(source);
	if (length > num) { // strncpy result may not truncated if destination buffer is too small
		llsec_throw(LLSEC_ERROR_OOM, "Cannot copy result string: buffer too small");
	} else {
		char *dest = strncpy((char *)destination, source, length);
		LLSEC_GENERIC_DEBUG_TRACE("\tstrncpy(%p, %p, %d) = %p\n", destination, source, length, dest);
		(void)dest;
		// if (length != num) destination[length] = '\0'; // not needed: take advantage that
		// destination buffer is zero-initialized and SNI.toJavaString(cString) does not need a
		// null-terminated string if filled completely
	}
}

void * llsec_calloc(size_t num, size_t size) {
	void *ptr = LLSEC_CALLOC_IMPL(num, size);
	LLSEC_GENERIC_DEBUG_TRACE("\tLLSEC_CALLOC_IMPL(%d, %d) = %p\n", num, size, ptr);
	return ptr;
}

void llsec_free(void *ptr) {
	LLSEC_FREE_IMPL(ptr);
	LLSEC_GENERIC_DEBUG_TRACE("\tLLSEC_FREE_IMPL(%p)\n", ptr);
}

void llsec_throw(int32_t errorCode, const char *message) {
	int32_t ret = SNI_throwNativeException(errorCode, message);
	LLSEC_GENERIC_DEBUG_TRACE("\tSNI_throwNativeException(%d, \"%s\") = %d\n", errorCode, message, ret);
	LLSEC_ASSERT(("SNI_throwNativeException() failed", ret == SNI_OK));
}

MICROEJ_ASYNC_WORKER_job_t * llsec_allocate_job(SNI_callback retry_callback) {
	MICROEJ_ASYNC_WORKER_handle_t *async_worker = &llsec_worker;
	MICROEJ_ASYNC_WORKER_job_t *job = MICROEJ_ASYNC_WORKER_allocate_job(async_worker, retry_callback);
	// cppcheck-suppress [misra-c2012-11.1]: function pointer cast to display the symbol address.
	LLSEC_GENERIC_DEBUG_TRACE("\tMICROEJ_ASYNC_WORKER_allocate_job(%p, %p) = %p\n", async_worker,
	                          (void *)retry_callback, job);
	return job;
}

int32_t llsec_async_exec(MICROEJ_ASYNC_WORKER_job_t *job, MICROEJ_ASYNC_WORKER_action_t action,
                         SNI_callback on_done_callback) {
	MICROEJ_ASYNC_WORKER_handle_t *async_worker = &llsec_worker;
	MICROEJ_ASYNC_WORKER_status_t status = MICROEJ_ASYNC_WORKER_async_exec(async_worker, job,
	                                                                       action, on_done_callback);
	// cppcheck-suppress [misra-c2012-11.1]: function pointer cast to display the symbol address.
	LLSEC_GENERIC_DEBUG_TRACE("\tMICROEJ_ASYNC_WORKER_async_exec(%p, %p, %p, %p) = %d\n", async_worker,
	                          job, (void *)action, (void *)on_done_callback, status);
	return (status == MICROEJ_ASYNC_WORKER_OK) ? LLSEC_SUCCESS : LLSEC_ERROR;
}

void llsec_free_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	MICROEJ_ASYNC_WORKER_handle_t *async_worker = &llsec_worker;
	MICROEJ_ASYNC_WORKER_status_t status = MICROEJ_ASYNC_WORKER_free_job(async_worker, job);
	LLSEC_GENERIC_DEBUG_TRACE("\tMICROEJ_ASYNC_WORKER_free_job(%p, %p) = %d\n", async_worker, job,
	                          status);
	LLSEC_ASSERT(("MICROEJ_ASYNC_WORKER_free_job() failed", status == MICROEJ_ASYNC_WORKER_OK));
}

BSP_DECLARE_WEAK_FCNT WOLFSSL_HEAP_HINT * llsec_wolfssl_get_heap(void) {
	// If NULL is provided to WolfSSL functions, the system heap is used by default.
	return NULL;
}

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

#if !defined(NO_ASN) && !defined(NO_ASN_TIME)

/**
 * @brief Function used by Wolfcrypt to determine the epoch time for the certificate validation.
 *
 * @return  Number of seconds that have elapsed since January 1, 1970.
 */
static time_t time_cb(time_t *t) {
	time_t current_time = microej_time_get_current_time(MICROEJ_FALSE);
	if (NULL != t) {
		*t = current_time;
	}
	return current_time;
}

/**
 * @brief Function called to set the function used by Wolfcrypt to determine the epoch time for certificate validation.
 *
 */
static void llsec_init_time_function(void) {
	(void)wc_SetTimeCb(time_cb);
}

#endif

static void llsec_impl_initialize_worker(void) {
	// cppcheck-suppress [misra-c2012-11.8]: String casts conform to MICROEJ_ASYNC_WORKER_initialize function
	// definitions.
	MICROEJ_ASYNC_WORKER_status_t status = MICROEJ_ASYNC_WORKER_initialize(&llsec_worker, (uint8_t *)"MicroEJ LLSEC",
	                                                                       llsec_worker_stack, LLSEC_WORKER_PRIORITY);
	if (status == MICROEJ_ASYNC_WORKER_INVALID_ARGS) {
		llsec_throw(status, "Invalid argument for SEC async worker");
	} else if (status == MICROEJ_ASYNC_WORKER_ERROR) {
		llsec_throw(status, "Error while initializing SEC async worker");
	} else {
		// Default case: MICROEJ_ASYNC_WORKER_OK
		// Allocate Secure Stack for potential NSC Calls.
		// This needs to happen AFTER the thread is created, since
		// the stack is associated with llsec_worker task.
		if (false == RTOS_PASSTEST(
				RTOS_THREAD_SECURE_STACK_ALLOCATE(&llsec_worker.task, TASK_MICROEJ_SEC_SECURE_STACK_SIZE))) {
			Error_Handler();
		}
	}
}

static void llsec_wolfcrypt_initialize_rng(void) {
	int return_code = LLSEC_SUCCESS;
	const char *seed = llsec_gen_random_str_internal(LLSEC_RANDOM_SEED_SIZE);
	WOLFSSL_HEAP_HINT *pHint = llsec_wolfssl_get_heap();

#if !defined(NO_ASN) && !defined(NO_ASN_TIME)
	// init the time function
	llsec_init_time_function();
#endif

	if (NULL == seed) {
		LLSEC_GENERIC_DEBUG_TRACE("%s llsec_gen_random_str_internal: allocation error\n", __func__);
		return_code = LLSEC_ERROR;
	}
	if (LLSEC_SUCCESS == return_code) {
		llsec_wolfcrypt_RNG = wc_rng_new((byte *)seed, (word32)strlen(seed), pHint);
		if (NULL == llsec_wolfcrypt_RNG) {
			return_code = LLSEC_ERROR;
		}
	}
	if (LLSEC_SUCCESS != return_code) {
		llsec_throw(LLSEC_ERROR, "Could not initialize LLSEC WolfCrypt adaptation layer implementation");
	}
}

// --------------------------------------------------------------------------------
// Public functions
// --------------------------------------------------------------------------------

// see LLSEC_impl.h
void LLSEC_IMPL_initialize(void) {
	llsec_impl_initialize_worker();
	llsec_wolfcrypt_initialize_rng();
}

/**
 * @brief Determines the error message from a Wolfcrypt error code.
 * @param error_code Wolfcrypt error code.
 *
 * @return C string containing the error message.
 */
char const * llsec_wc_error_message(int error_code) {
	char const *error_message;
	switch (error_code) {
	case 0:
		error_message = "Ok";
		break;
	case BAD_FUNC_ARG:
	case BUFFER_E:
		error_message = wc_GetErrorString(error_code);
		break;
	case SIG_TYPE_E:
		error_message = "Signature type not enabled/available";
		break;
	default:
		error_message = wc_GetErrorString(error_code);
		break;
	}
	return error_message;
}

/**
 * @brief Generates random string function.
 * @param[in] Length the string length.
 *
 * @return Pointer to random string.
 */
char * llsec_gen_random_str_internal(int length) {
	char *return_code = NULL;
	char *str_ran;
	str_ran = (char *)llsec_calloc(1, length);

	if (NULL == str_ran) {
		LLSEC_RANDOM_DEBUG_TRACE("Random string malloc failed");
		while (1) {
		}
		;
	} else {
		srand((unsigned int)microej_time_get_current_time(0));

		int idx;
		for (idx = 0; idx < (length - 1); idx++) {
			int flag = rand() % 3;
			switch (flag) {
			case 0:
				// cppcheck-suppress [misra-c2012-10.8] : Number in [0, 25] range
				str_ran[idx] = 'A' + (uint8_t)(rand() % 26);
				break;
			case 1:
				// cppcheck-suppress [misra-c2012-10.8] : Number in [0, 25] range
				str_ran[idx] = 'a' + (uint8_t)(rand() % 26);
				break;
			case 2:
				// cppcheck-suppress [misra-c2012-10.8] : Number in [0, 10] range
				str_ran[idx] = '0' + (uint8_t)(rand() % 10);
				break;
			default:
				str_ran[idx] = 'x';
				break;
			}
		}
		str_ran[length - 1] = '\0';
		return_code = str_ran;
	}

	return return_code;
}

#ifndef NO_RSA
/**
 * @brief Determines the Wolfcrpyt hashtype value from a LLSEC_RSA_CIPHER_oaep_hash_algorithm value.
 *
 * @return Wolfcrypt hashType enum value.
 */
enum wc_HashType llsec_rsa_get_wc_hash(int32_t oaep_hash_algorithm) {
	enum wc_HashType return_value;
	switch (oaep_hash_algorithm) {
	case OAEP_HASH_SHA_1_ALGORITHM:
		return_value = WC_HASH_TYPE_SHA;
		break;
	case OAEP_HASH_SHA_256_ALGORITHM:
		return_value = WC_HASH_TYPE_SHA256;
		break;
	default:
		return_value = WC_HASH_TYPE_NONE;
		break;
	}

	return return_value;
}

/**
 * @brief Determines the Wolfcrpyt padding type value from a LLSEC_RSA_CIPHER_padding_type value.
 *
 * @return Wolfcrypt padding type value.
 */
int  llsec_rsa_get_padding(int32_t type) {
	int return_value;
	switch (type) {
	case PAD_PKCS1_TYPE:
		return_value = WC_RSA_PKCSV15_PAD;
		break;
	case PAD_OAEP_MGF1_TYPE:
		return_value = WC_RSA_OAEP_PAD;
		break;
	default:
		return_value = WC_RSA_NO_PAD;
		break;
	}

	return return_value;
}

#endif // NO_RSA

/**
 * @brief Determines the Wolfcrypt curve ID for ECC algorithm, from a standard name.
 * @param stdname C string containing the curve standard name for ECC algorithm.
 *
 * @return Worlfcrypt curve ID.
 */
ecc_curve_id llsec_ecc_get_wc_curve_id(const uint8_t *stdname) {
	// standard curve names / ids
	static const char *curve_stdnames[] = {
		"secp192r1",
		"prime192v2",
		"prime192v3",
		"prime239v1",
		"prime239v2",
		"prime239v3",
		"secp256r1",
		"secp112r1",
		"secp112r2",
		"secp128r1",
		"secp128r2",
		"secp160r1",
		"secp160r2",
		"secp224r1",
		"secp384r1",
		"secp521r1",
		"secp160k1",
		"secp192k1",
		"secp224k1",
		"secp256k1",
		"brainpoolp160r1",
		"brainpoolp192r1",
		"brainpoolp224r1",
		"brainpoolp256r1",
		"brainpoolp320r1",
		"brainpoolp384r1",
		"brainpoolp512r1",
		"sm2p256v1",
	};

	static ecc_curve_id curve_ids[] = {
		ECC_SECP192R1,
		ECC_PRIME192V2,
		ECC_PRIME192V3,
		ECC_PRIME239V1,
		ECC_PRIME239V2,
		ECC_PRIME239V3,
		ECC_SECP256R1,
		ECC_SECP112R1,
		ECC_SECP112R2,
		ECC_SECP128R1,
		ECC_SECP128R2,
		ECC_SECP160R1,
		ECC_SECP160R2,
		ECC_SECP224R1,
		ECC_SECP384R1,
		ECC_SECP521R1,
		ECC_SECP160K1,
		ECC_SECP192K1,
		ECC_SECP224K1,
		ECC_SECP256K1,
		ECC_BRAINPOOLP160R1,
		ECC_BRAINPOOLP192R1,
		ECC_BRAINPOOLP224R1,
		ECC_BRAINPOOLP256R1,
		ECC_BRAINPOOLP320R1,
		ECC_BRAINPOOLP384R1,
		ECC_BRAINPOOLP512R1,
		ECC_SM2P256V1,
	};

	uint8_t index;
	ecc_curve_id result = ECC_CURVE_INVALID;
	for (index = 0; index < (sizeof(curve_ids) / sizeof(ecc_curve_id)); index++) {
		if (0 == strcmp((const char *)curve_stdnames[index], (const char *)stdname)) {
			result = curve_ids[index];
		}
	}
	return result;
}

/**
 * @brief Determines the Wolfcrypt hash type ID from the standard name of the algorithm.
 * @param stdname C string containing the name of the hash algorithm.
 *
 * @return Wolfcrypt hash algorithm ID
 */
enum wc_HashType llsec_sign_get_wc_hash_type(const uint8_t *stdname) {
	static enum wc_HashType hash_type_ids[] ={
		WC_HASH_TYPE_NONE,
		WC_HASH_TYPE_MD2,
		WC_HASH_TYPE_MD4,
		WC_HASH_TYPE_MD5,
		WC_HASH_TYPE_SHA,
		WC_HASH_TYPE_SHA224,
		WC_HASH_TYPE_SHA256,
		WC_HASH_TYPE_SHA384,
		WC_HASH_TYPE_SHA512,
		WC_HASH_TYPE_MD5_SHA,
		WC_HASH_TYPE_SHA3_224,
		WC_HASH_TYPE_SHA3_256,
		WC_HASH_TYPE_SHA3_384,
		WC_HASH_TYPE_SHA3_512,
		WC_HASH_TYPE_BLAKE2B,
		WC_HASH_TYPE_BLAKE2S,
		#ifndef WOLFSSL_NOSHA512_224
		WC_HASH_TYPE_SHA512_224,
		#endif
		#ifndef WOLFSSL_NOSHA512_256
		WC_HASH_TYPE_SHA512_256,
		#endif
		#ifdef WOLFSSL_SHAKE128
		WC_HASH_TYPE_SHAKE128,
		#endif
		#ifdef WOLFSSL_SHAKE256
		WC_HASH_TYPE_SHAKE25,
		#endif
		#ifdef WOLFSSL_SM3
		WC_HASH_TYPE_SM3,
		#endif
	};

	static const char *hash_type_names[] = {
		"NONE",
		"MD2",
		"MD4",
		"MD5",
		"SHA",
		"SHA224",
		"SHA256",
		"SHA384",
		"SHA512",
		"MD5_SHA",
		"SHA3_224",
		"SHA3_256",
		"SHA3_384",
		"SHA3_512",
		"BLAKE2B",
		"BLAKE2S",
		#ifndef WOLFSSL_NOSHA512_224
		"SHA512_224",
		#endif
		#ifndef WOLFSSL_NOSHA512_256
		"SHA512_256",
		#endif
		#ifdef WOLFSSL_SHAKE128
		"SHAKE128",
		#endif
		#ifdef WOLFSSL_SHAKE256
		"SHAKE25",
		#endif
		#ifdef WOLFSSL_SM3
		"SM3",
		#endif
	};

	uint8_t index;
	enum wc_HashType result = WC_HASH_TYPE_NONE;
	for (index=0; index < (sizeof(hash_type_ids) / sizeof(enum wc_HashType)); index++) {
		if (0 == strcmp((const char *)hash_type_names[index], (const char *)stdname)) {
			result = hash_type_ids[index];
		}
	}
	return result;
}

/**
 * @brief   Determines the format of the certificate by decoding it. If cert_object is non-NULL, the decoded certificate
 * is stored at the location pointed to by cert_object.
 *   If check_error is non-NULL, the certificate is checked and the result of the check is stored in this variable.
 *
 * @param[in]  cert_data  Poiner to the buffer containing the certificate.
 * @param[in]  len  Size of the certificate data (in byte).
 * @param[out] cert_object  Pointer pointer to the decoded certificate structure.
 * @param[out]  check_error  Pointer to a variable to store the certificate validation result.
 *
 * @return     format of the encoded certificate:  CERT_DER_FORMAT or CERT_PEM_FORMAT.
 *
 */
int32_t get_x509_certificate_format(int8_t *cert_data, int32_t len, DecodedCert **cert_object,
                                    int32_t *check_error) {
	int return_code = LLSEC_X509_UNKNOWN_FORMAT;
	WOLFSSL_HEAP_HINT *pHint = llsec_wolfssl_get_heap();
	int wolfcrypt_rc;

	if (NULL != cert_object) {
		*cert_object = NULL;
	}

	/* Allocate a new X509 certificate */
	DecodedCert *new_cert = NULL;
	new_cert = (DecodedCert *)llsec_calloc(1, sizeof(DecodedCert));
	if (NULL == new_cert) {
		return_code = J_MEMORY_ERROR;
	} else {
		/* Initialize the X509 certificate */
		wc_InitDecodedCert(new_cert, (byte const *)cert_data, len, pHint);

		/* Parse the X509 DER certificate */
		if (NULL == check_error) {
			wolfcrypt_rc = wc_ParseCert(new_cert, TRUSTED_PEER_TYPE, NO_VERIFY, NULL);
		} else {
			wolfcrypt_rc = wc_ParseCert(new_cert, TRUSTED_PEER_TYPE, VERIFY, NULL);
			*check_error = wolfcrypt_rc;
		}
		if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
			/* Encoded DER  certificate */
			return_code = CERT_DER_FORMAT;
			if (NULL != cert_object) {
				*cert_object = new_cert;
			}
		} else {
			LLSEC_X509_DEBUG_TRACE("wc_ParseCert(DER) failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
			LLSEC_X509_DEBUG_TRACE("Now trying with wc_ParseCert(PEM)...\n");
		}
		if (NULL == cert_object) {
			wc_FreeDecodedCert(new_cert);
			llsec_free(new_cert);
		}
	}

	if (CERT_DER_FORMAT != return_code) {
		DerBuffer *der_buffer = NULL;
		if (NULL == new_cert) {
			return_code = J_MEMORY_ERROR;
		} else {
			/* Convert PEM to DER */
			wolfcrypt_rc = wc_PemToDer((byte const *)cert_data, len, CERT_TYPE, &der_buffer, pHint, NULL, NULL);
			if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
				int32_t der_len = der_buffer->length;
				return_code = CERT_PEM_FORMAT;
				if (NULL != cert_object) {
					new_cert = llsec_calloc(1, sizeof(DecodedCert));
					if (NULL == new_cert) {
						return_code = J_MEMORY_ERROR;
					} else {
						/* Initialize the X509 certificate */
						wc_InitDecodedCert(new_cert, (byte const *)der_buffer->buffer, der_len, pHint);

						/* Parse the X509 DER certificate */
						if (NULL == check_error) {
							wolfcrypt_rc = wc_ParseCert(new_cert, TRUSTED_PEER_TYPE, NO_VERIFY, NULL);
						} else {
							wolfcrypt_rc = wc_ParseCert(new_cert, TRUSTED_PEER_TYPE, VERIFY, NULL);
							*check_error = wolfcrypt_rc;
						}
						if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
							*cert_object = new_cert;
						} else {
							LLSEC_X509_DEBUG_TRACE("wc_ParseCert(PEM) failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
						}
					}
				}
			} else {
				LLSEC_X509_DEBUG_TRACE("wc_PemToDer() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
				return_code = J_CERT_PARSE_ERROR;
			}
			wc_FreeDer(&der_buffer);
		}
	}

	return return_code;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
