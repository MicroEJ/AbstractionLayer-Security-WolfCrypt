/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - Signature.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_ERRORS.h>
#include <LLCRYPTO_SIG_impl.h>
#include <LLCRYPTO_common.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

struct LLCRYPTO_SIG_algorithm {
	char *name;
	char *digest_name;
	char *oid;
	enum wc_HashType hash_type;
	enum wc_SignatureType sig_type;
	word32 key_len;
	LLCRYPTO_algo_type algo_type;
};

// --------------------------------------------------------------------------------
// Constant declarations
// --------------------------------------------------------------------------------

static LLCRYPTO_SIG_algorithm available_sig_algorithms[] = {
#ifndef NO_RSA
	{
		.name = "SHA256withRSA",
		.digest_name = "SHA-256",
		.oid = "1.2.840.113549.1.1.11",
		.hash_type = WC_HASH_TYPE_SHA256,
		.sig_type = WC_SIGNATURE_TYPE_RSA_W_ENC,
		.key_len = sizeof(RsaKey),
		.algo_type = ALGO_RSA
	},
#endif // NO_RSA
	{
		.name = "SHA256withECDSA",
		.digest_name = "SHA-256",
		.oid = "1.2.840.10045.4.3.2",
		.hash_type = WC_HASH_TYPE_SHA256,
		.sig_type = WC_SIGNATURE_TYPE_ECC,
		.key_len = sizeof(ecc_key),
		.algo_type = ALGO_ECDSA
	}
};

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

/**
 * @brief   Encodes a digital signature into the output buffer, and returns the size of the encoded signature created.
 *
 * @param[in]  out  Pointer to the buffer where the encoded signature will be written.
 * @param[in]  hash_type  hash type used to generate the signature. Valid options, depending on Wolfcrypt
 * configurations, are enum wc_HashType  value.
 * @param[in]  digest  Pointer to the digest to use to encode the signature.
 * @param[in]  digest_length Length of the buffer containing the digest
 *
 * @return     Size of encoded signature if the creation is successful,  SNI_IGNORED_RETURNED_VALUE otherwise.
 *
 * @note Throws NativeIOException on error.
 *
 */
static int32_t llcrypto_sig_encodeDigestOid(uint8_t *out, enum wc_HashType hash_type, uint8_t *digest,
                                            int32_t *digest_length, int32_t *rc, int32_t *error_code,
                                            const char **reason) {
	LLCRYPTO_SIG_DEBUG_TRACE("\t%s(%p, %d, %p, %d, %p, %p, %p)\n", __func__, out, hash_type, digest,
	                         *digest_length, rc, error_code, reason);
	int32_t result = LLCRYPTO_SUCCESS;

	int oid = 0;
	if (LLCRYPTO_SUCCESS == result) {
		int wolfcrypt_rc = wc_HashGetOID(hash_type);
		LLCRYPTO_SIG_DEBUG_TRACE("\t\twc_HashGetOID(%d) = %d\n", hash_type, wolfcrypt_rc);
		if (wolfcrypt_rc < 0) {
			result = LLCRYPTO_ERROR;
			*rc = LLCRYPTO_JOB_EXCEPTION;
			*error_code = wolfcrypt_rc;
			*reason = "Could not retrieve the OID for this signature's digest algorithm";
		} else {
			oid = wolfcrypt_rc;
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		int wolfcrypt_rc = wc_EncodeSignature(out, digest, *digest_length, oid);
		LLCRYPTO_SIG_DEBUG_TRACE("\t\twc_EncodeSignature(%p, %p, %d, %d) = %d\n", out, digest,
		                         *digest_length, oid, wolfcrypt_rc);
		if (wolfcrypt_rc < 0) {
			result = LLCRYPTO_ERROR;
			*rc = LLCRYPTO_JOB_EXCEPTION;
			*error_code = wolfcrypt_rc;
		} else {
			*digest_length = wolfcrypt_rc;
		}
	}

	LLCRYPTO_SIG_DEBUG_TRACE("\t\t=> SUCCESS (encoded length: %d)\n", *digest_length);
	return result;
}

static void LLCRYPTO_SIG_IMPL_sign_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLCRYPTO_SIG_DEBUG_TRACE("%s(%p)\n", __func__, job);
	LLCRYPTO_SIG_sign_params_t *params = job->params;
	struct LLCRYPTO_SIG_algorithm *algorithm = params->algorithm;
	const LLCRYPTO_priv_key *priv_key = params->private_key;
	uint8_t *digest = params->digest;
	int32_t digest_length = params->digest_length;

	int32_t result = LLCRYPTO_SUCCESS;

	if (LLCRYPTO_SUCCESS == result) {
		if (priv_key->algo_type != algorithm->algo_type) {
			LLCRYPTO_SIG_DEBUG_TRACE("\tcheck-failure: Key type does not match signature algorithm type\n");
			result = LLCRYPTO_ERROR;
			params->rc = LLCRYPTO_JOB_EXCEPTION;
			params->error_code = LLCRYPTO_ERROR;
			params->reason = "Private key not compatible with signature algorithm";
		}
	}

#ifndef NO_RSA
	// Workaround: https://github.com/wolfSSL/wolfssl/issues/5981
	uint8_t *encodedDigest = NULL;
	if (LLCRYPTO_SUCCESS == result) {
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			encodedDigest = (uint8_t *)llcrypto_calloc(1, digest_length + MAX_DER_DIGEST_ASN_SZ);
			if (NULL == encodedDigest) {
				result = LLCRYPTO_ERROR;
				params->rc = LLCRYPTO_JOB_EXCEPTION;
				params->error_code = LLCRYPTO_ERROR_OOM;
				params->reason = "Could not allocate buffer to encode digest";
			}
		}
	}
	if (LLCRYPTO_SUCCESS == result) {
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			result = llcrypto_sig_encodeDigestOid(encodedDigest, algorithm->hash_type, digest,
			                                      &digest_length, &params->rc,
			                                      &params->error_code, &params->reason);
		}
	}

	if (LLCRYPTO_SUCCESS == result) {
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			digest = encodedDigest;
		}
	}
#endif // NO_RSA

	if (LLCRYPTO_SUCCESS == result) {
		int wolfcrypt_rc = wc_SignatureGenerateHash_ex(algorithm->hash_type, algorithm->sig_type,
		                                               digest, digest_length,
		                                               params->signature, (word32 *)&params->signature_length,
		                                               params->private_key->any_key, algorithm->key_len,
		                                               llcrypto_wolfcrypt_RNG, 0);
		LLCRYPTO_SIG_DEBUG_TRACE("\twc_SignatureGenerateHash(%d, %d, %p, %d, %p, %d, %p, %d, %p) = %d\n",
		                         algorithm->hash_type, algorithm->sig_type, digest, digest_length,
		                         params->signature, params->signature_length,
		                         params->private_key->any_key, algorithm->key_len, llcrypto_wolfcrypt_RNG,
		                         wolfcrypt_rc);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
			params->rc = LLCRYPTO_SUCCESS;
		} else {
			params->rc = LLCRYPTO_JOB_EXCEPTION;
			params->error_code = wolfcrypt_rc;
			params->reason = llcrypto_wc_error_message(wolfcrypt_rc);
		}
	}

#ifndef NO_RSA
	if (encodedDigest != NULL) {
		llcrypto_free(encodedDigest);
	}
#endif // NO_RSA

	LLCRYPTO_SIG_DEBUG_TRACE("\t=> DONE\n");
}

static int32_t LLCRYPTO_SIG_IMPL_sign_job_done(int32_t algorithm_id, uint8_t *signature, int32_t signature_length,
                                               int32_t private_key_id, uint8_t *digest, int32_t digest_length) {
	LLCRYPTO_SIG_DEBUG_TRACE(
		"%s(algorithm_id=%d, signature=%p, signature_length=%d, private_key_id=%d, digest=%p, digest_length=%d)\n",
		__func__, algorithm_id, signature, signature_length, private_key_id, digest, digest_length);
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	LLCRYPTO_UNUSED_PARAM(signature_length);
	LLCRYPTO_UNUSED_PARAM(private_key_id);
	LLCRYPTO_UNUSED_PARAM(digest);
	LLCRYPTO_UNUSED_PARAM(digest_length);

	int32_t return_code = 0;
	int32_t result = LLCRYPTO_SUCCESS;

	MICROEJ_ASYNC_WORKER_job_t *job = NULL;
	if (result == LLCRYPTO_SUCCESS) {
		job = MICROEJ_ASYNC_WORKER_get_job_done();
		if (job == NULL) {
			llcrypto_throw(LLCRYPTO_ERROR, "Internal error: cannot retrieve async worker job done");
			result = LLCRYPTO_JOB_EXCEPTION;
		} else {
			LLCRYPTO_SIG_DEBUG_TRACE("\tjob=%p\n", job);
		}
	}

	LLCRYPTO_SIG_sign_params_t *params = NULL;
	if (result == LLCRYPTO_SUCCESS) {
		params = (LLCRYPTO_SIG_sign_params_t *)job->params;
		result = params->rc;

		switch (result) {
		case LLCRYPTO_SUCCESS:
			return_code = params->signature_length;
			llcrypto_memcpy(signature, params->signature, params->signature_length);
			break;
		case LLCRYPTO_JOB_NOT_COMPLETED:
			LLCRYPTO_ASSERT(("SNI callback executed before the async task has completed", false));
			llcrypto_throw(LLCRYPTO_ERROR, "Internal error: SNI callback executed before the async task has completed");
			return_code = SNI_IGNORED_RETURNED_VALUE;
			break;
		case LLCRYPTO_JOB_EXCEPTION:
		default:
			LLCRYPTO_ASSERT(params->reason != NULL);
			if (params->reason == NULL) { // fallback if no assert
				params->reason = "Internal Error";
			}
			llcrypto_throw(params->error_code, params->reason);
			return_code = SNI_IGNORED_RETURNED_VALUE;
			break;
		}
	}

	if (params != NULL) {
		llcrypto_free(params->digest);
		llcrypto_free(params->signature);
	}

	if (job != NULL) {
		llcrypto_free_job(job);
	}

	LLCRYPTO_SIG_DEBUG_TRACE("\t=> %d\n", return_code);
	return return_code;
}

static void LLCRYPTO_SIG_IMPL_verify_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLCRYPTO_SIG_DEBUG_TRACE("%s(%p)\n", __func__, job);

	LLCRYPTO_SIG_verify_params_t *params = job->params;
	LLCRYPTO_SIG_algorithm *algorithm = params->algorithm;
	const LLCRYPTO_pub_key *pub_key = params->public_key;
	uint8_t *digest = params->digest;
	int32_t digest_length = params->digest_length;

	int32_t result = LLCRYPTO_SUCCESS;

	if (LLCRYPTO_SUCCESS == result) {
		if (pub_key->algo_type != algorithm->algo_type) {
			LLCRYPTO_SIG_DEBUG_TRACE("\tcheck-failure: Key type does not match signature algorithm type\n");
			result = LLCRYPTO_ERROR;
			params->rc = LLCRYPTO_JOB_EXCEPTION;
			params->error_code = LLCRYPTO_ERROR;
			params->reason = "Public key not compatible with signature algorithm";
		}
	}

#ifndef NO_RSA
	// Workaround: https://github.com/wolfSSL/wolfssl/issues/5981
	uint8_t *encodedDigest = NULL;
	if (LLCRYPTO_SUCCESS == result) {
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			encodedDigest = (uint8_t *)llcrypto_calloc(1, digest_length + MAX_DER_DIGEST_ASN_SZ);
			if (NULL == encodedDigest) {
				result = LLCRYPTO_ERROR;
				params->rc = LLCRYPTO_JOB_EXCEPTION;
				params->error_code = LLCRYPTO_ERROR_OOM;
				params->reason = "Could not allocate buffer to encode digest";
			}
		}
	}
	if (LLCRYPTO_SUCCESS == result) {
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			result = llcrypto_sig_encodeDigestOid(encodedDigest, algorithm->hash_type, digest, &digest_length,
			                                      &params->rc, &params->error_code, &params->reason);
			digest = encodedDigest;
		}
	}
#endif // NO_RSA

	if (LLCRYPTO_SUCCESS == result) {
		int wolfcrypt_rc = wc_SignatureVerifyHash(algorithm->hash_type, algorithm->sig_type,
		                                          digest, digest_length,
		                                          params->signature, params->signature_length,
		                                          params->public_key->any_key, algorithm->key_len);
		LLCRYPTO_SIG_DEBUG_TRACE("\twc_SignatureVerifyHash(%d, %d, %p, %d, %p, %d, %p, %d) = %d\n",
		                         algorithm->hash_type, algorithm->sig_type, digest, digest_length,
		                         params->signature, params->signature_length,
		                         params->public_key->any_key, algorithm->key_len, wolfcrypt_rc);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
			params->rc = LLCRYPTO_SUCCESS;
		} else if (SIG_VERIFY_E == wolfcrypt_rc) {
			params->rc = LLCRYPTO_ERROR;
		} else {
			params->rc = LLCRYPTO_JOB_EXCEPTION;
			params->error_code = wolfcrypt_rc;
			params->reason = llcrypto_wc_error_message(wolfcrypt_rc);
		}
	}

	LLCRYPTO_SIG_DEBUG_TRACE("=> DONE\n");
}

static uint8_t LLCRYPTO_SIG_IMPL_verify_job_done(int32_t algorithm_id, uint8_t *signature,
                                                 int32_t signature_length, int32_t public_key_id,
                                                 uint8_t *digest, int32_t digest_length) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_SIG_DEBUG_TRACE("%s(%p, %p, %d, %p, %p, %d)\n", __func__, (void *)algorithm_id, signature,
	                         signature_length, (void *)public_key_id, digest, digest_length);
	LLCRYPTO_UNUSED_PARAM(algorithm_id);
	LLCRYPTO_UNUSED_PARAM(signature);
	LLCRYPTO_UNUSED_PARAM(signature_length);
	LLCRYPTO_UNUSED_PARAM(public_key_id);
	LLCRYPTO_UNUSED_PARAM(digest);
	LLCRYPTO_UNUSED_PARAM(digest_length);

	int32_t result = LLCRYPTO_SUCCESS;

	int8_t rc = JFALSE;

	MICROEJ_ASYNC_WORKER_job_t *job = NULL;
	if (result == LLCRYPTO_SUCCESS) {
		job = MICROEJ_ASYNC_WORKER_get_job_done();
		if (job == NULL) {
			result = LLCRYPTO_ERROR;
			llcrypto_throw(LLCRYPTO_ERROR, "Internal error: cannot retrieve async worker job done");
		}
	}

	LLCRYPTO_SIG_verify_params_t *params = NULL;
	if (result == LLCRYPTO_SUCCESS) {
		params = (LLCRYPTO_SIG_verify_params_t *)job->params;

		switch (params->rc) {
		case LLCRYPTO_SUCCESS:
			rc = JTRUE;
			break;
		case LLCRYPTO_ERROR:
			rc = JFALSE;
			break;
		case LLCRYPTO_JOB_NOT_COMPLETED:
			LLCRYPTO_ASSERT(("SNI callback executed before the async task has completed", false));
			llcrypto_throw(LLCRYPTO_ERROR, "Internal error: SNI callback executed before the async task has completed");
			rc = SNI_IGNORED_RETURNED_VALUE;
			break;
		case LLCRYPTO_JOB_EXCEPTION:
		default:
			LLCRYPTO_ASSERT(params->reason != NULL);
			if (params->reason == NULL) { // fallback if no assert
				params->reason = "Internal Error";
			}
			rc = SNI_IGNORED_RETURNED_VALUE;
			llcrypto_throw(params->error_code, params->reason);
			break;
		}
	}

	if (params != NULL) {
		llcrypto_free(params->digest);
		llcrypto_free(params->signature);
	}

	if (job != NULL) {
		llcrypto_free_job(job);
	}

	LLCRYPTO_SIG_DEBUG_TRACE("\t=> %d\n", rc);
	return rc;
}

// --------------------------------------------------------------------------------
// LLCRYPTO_KEY_FACTORY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLCRYPTO_SIG_IMPL_get_algorithm_description(uint8_t *algorithm_name,
                                                    uint8_t *digest_algorithm_name,
                                                    int32_t digest_algorithm_name_length) {
	LLCRYPTO_SIG_DEBUG_TRACE("%s(\"%s\", %p, %d)\n", __func__, algorithm_name, digest_algorithm_name,
	                         digest_algorithm_name_length);
	int32_t return_code = LLCRYPTO_ERROR;

	int32_t nb_algorithms = sizeof(available_sig_algorithms) / sizeof(LLCRYPTO_SIG_algorithm);
	LLCRYPTO_SIG_algorithm *algorithm = &available_sig_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			llcrypto_strncpy(digest_algorithm_name, algorithm->digest_name, digest_algorithm_name_length);
			// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
			return_code = (int32_t)algorithm;
			break;
		}
		algorithm++;
	}

	LLCRYPTO_SIG_DEBUG_TRACE("\t=> %d (digest algorithm: \"%s\")\n", return_code, digest_algorithm_name);
	return return_code;
}

// See the header file for the function documentation
void LLCRYPTO_SIG_IMPL_get_algorithm_oid(uint8_t *algorithm_name, uint8_t *oid, int32_t oid_length) {
	LLCRYPTO_SIG_DEBUG_TRACE("%s(\"%s\", %p, %d)\n", __func__, algorithm_name, oid, oid_length);

	int32_t nb_algorithms = sizeof(available_sig_algorithms) / sizeof(LLCRYPTO_SIG_algorithm);
	LLCRYPTO_SIG_algorithm *algorithm = &available_sig_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			llcrypto_strncpy(oid, algorithm->oid, oid_length);
			break;
		}
		algorithm++;
	}
	if (0 > nb_algorithms) {
		llcrypto_throw(LLCRYPTO_ERROR, "Algorithm not found");
	}

	LLCRYPTO_SIG_DEBUG_TRACE("\t=> oid: \"%s\"\n", oid);
}

// See the header file for the function documentation
int32_t LLCRYPTO_SIG_IMPL_sign(int32_t algorithm_id, uint8_t *signature, int32_t signature_length,
                               int32_t private_key_id, uint8_t *digest, int32_t digest_length) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_SIG_DEBUG_TRACE("%s(%p, %p, %d, %p, %p, %d)\n", __func__, (void *)algorithm_id, signature,
	                         signature_length, (void *)private_key_id, digest, digest_length);
	LLCRYPTO_UNUSED_PARAM(signature);
	int result = LLCRYPTO_SUCCESS;

	MICROEJ_ASYNC_WORKER_job_t *job = NULL;
	if (result == LLCRYPTO_SUCCESS) {
		job = llcrypto_allocate_job((SNI_callback)LLCRYPTO_SIG_IMPL_sign);
		if (job == NULL) {
			result = LLCRYPTO_ERROR;
			// MICROEJ_ASYNC_WORKER_allocate_job() has thrown a NativeException
		}
	}

	LLCRYPTO_SIG_sign_params_t *params = NULL;
	if (result == LLCRYPTO_SUCCESS) {
		params = job->params;

		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		params->algorithm = (LLCRYPTO_SIG_algorithm *)algorithm_id;
		params->signature = NULL;
		params->signature_length = signature_length;
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		params->private_key = (LLCRYPTO_priv_key *)private_key_id;
		params->digest = NULL;
		params->digest_length = digest_length;

		params->signature = llcrypto_calloc(1, signature_length);
		if (params->signature == NULL) {
			result = LLCRYPTO_ERROR;
			llcrypto_throw(LLCRYPTO_ERROR_OOM, "Cannot allocate signature buffer");
		}
	}

	if (result == LLCRYPTO_SUCCESS) {
		params->digest = llcrypto_calloc(1, digest_length);
		if (params->digest != NULL) {
			llcrypto_memcpy(params->digest, digest, digest_length);
		} else {
			result = LLCRYPTO_ERROR;
			llcrypto_throw(LLCRYPTO_ERROR_OOM, "Cannot allocate digest buffer");
		}
	}

	if (result == LLCRYPTO_SUCCESS) {
		params->rc = LLCRYPTO_JOB_NOT_COMPLETED;
		if (LLCRYPTO_SUCCESS !=
		    llcrypto_async_exec(job, LLCRYPTO_SIG_IMPL_sign_job, (SNI_callback)LLCRYPTO_SIG_IMPL_sign_job_done)) {
			result = LLCRYPTO_ERROR;
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
		}
	}

	if (result == LLCRYPTO_ERROR) { // on error, free the allocated resources in reverse order
		if (params != NULL) {
			if (params->digest != NULL) {
				llcrypto_free(params->digest);
			}

			if (params->signature != NULL) {
				llcrypto_free(params->signature);
			}
		}

		if (job != NULL) {
			llcrypto_free_job(job);
		}
	}

	LLCRYPTO_SIG_DEBUG_TRACE("=> DONE\n");
	return SNI_IGNORED_RETURNED_VALUE; // either successfully suspended with callback or exception thrown
}

// See the header file for the function documentation
uint8_t LLCRYPTO_SIG_IMPL_verify(int32_t algorithm_id, uint8_t *signature, int32_t signature_length,
                                 int32_t public_key_id, uint8_t *digest, int32_t digest_length) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_SIG_DEBUG_TRACE("%s(%p, %p, %d, %p, %p, %d)\n", __func__, (void *)algorithm_id, signature,
	                         signature_length, (void *)public_key_id, digest, digest_length);
	int result = LLCRYPTO_SUCCESS;

	MICROEJ_ASYNC_WORKER_job_t *job = NULL;
	if (LLCRYPTO_SUCCESS == result) {
		job = llcrypto_allocate_job((SNI_callback)LLCRYPTO_SIG_IMPL_sign);
		if (job == NULL) {
			result = LLCRYPTO_ERROR;
			// MICROEJ_ASYNC_WORKER_allocate_job() has thrown a NativeException
		}
	}

	LLCRYPTO_SIG_verify_params_t *params = NULL;
	if (result == LLCRYPTO_SUCCESS) {
		params = job->params;
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		params->algorithm = (LLCRYPTO_SIG_algorithm *)algorithm_id;
		params->signature = NULL;
		params->signature_length = signature_length;
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		params->public_key = (LLCRYPTO_pub_key *)public_key_id;
		params->digest = NULL;
		params->digest_length = digest_length;

		params->signature = llcrypto_calloc(1, signature_length);
		if (params->signature != NULL) {
			llcrypto_memcpy(params->signature, signature, signature_length);
		} else {
			result = LLCRYPTO_ERROR;
			llcrypto_throw(LLCRYPTO_ERROR_OOM, "Cannot allocate signature buffer");
		}
	}

	if (result == LLCRYPTO_SUCCESS) {
		params->digest = llcrypto_calloc(1, digest_length);
		if (params->digest != NULL) {
			llcrypto_memcpy(params->digest, digest, digest_length);
		} else {
			result = LLCRYPTO_ERROR;
			llcrypto_throw(LLCRYPTO_ERROR_OOM, "Cannot allocate digest buffer");
		}
	}

	if (result == LLCRYPTO_SUCCESS) {
		params->rc = LLCRYPTO_JOB_NOT_COMPLETED;
		if (LLCRYPTO_SUCCESS !=
		    llcrypto_async_exec(job, LLCRYPTO_SIG_IMPL_verify_job, (SNI_callback)LLCRYPTO_SIG_IMPL_verify_job_done)) {
			result = LLCRYPTO_ERROR;
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
		}
	}

	if (result != LLCRYPTO_SUCCESS) { // on error, free the allocated resources in reverse order
		if (params != NULL) {
			if (params->digest != NULL) {
				llcrypto_free(params->digest);
			}
			if (params->signature != NULL) {
				llcrypto_free(params->signature);
			}
		}
		if (job != NULL) {
			llcrypto_free_job(job);
		}
	}

	LLCRYPTO_SIG_DEBUG_TRACE("=> DONE\n");
	return SNI_IGNORED_RETURNED_VALUE; // either successfully suspended with callback or exception thrown
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
