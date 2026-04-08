/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Signature.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_ERRORS.h>
#include <LLSEC_SIG_impl.h>
#include <LLSEC_common.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

struct LLSEC_SIG_algorithm {
	char *name;
	char *digest_name;
	char *oid;
	enum wc_HashType hash_type;
	enum wc_SignatureType sig_type;
	word32 key_len;
	LLSEC_algo_type algo_type;
};

// --------------------------------------------------------------------------------
// Constant declarations
// --------------------------------------------------------------------------------

static LLSEC_SIG_algorithm available_sig_algorithms[] = {
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
static int32_t llsec_sig_encodeDigestOid(uint8_t *out, enum wc_HashType hash_type, uint8_t *digest,
                                         int32_t *digest_length, int32_t *rc, int32_t *error_code,
                                         const char **reason) {
	LLSEC_SIG_DEBUG_TRACE("\t%s(%p, %d, %p, %d, %p, %p, %p)\n", __func__, out, hash_type, digest,
	                      *digest_length, rc, error_code, reason);
	int32_t result = LLSEC_SUCCESS;

	int oid = 0;
	if (LLSEC_SUCCESS == result) {
		int wolfcrypt_rc = wc_HashGetOID(hash_type);
		LLSEC_SIG_DEBUG_TRACE("\t\twc_HashGetOID(%d) = %d\n", hash_type, wolfcrypt_rc);
		if (wolfcrypt_rc < 0) {
			result = LLSEC_ERROR;
			*rc = LLSEC_ERROR_EXCEPTION;
			*error_code = wolfcrypt_rc;
			*reason = "Could not retrieve the OID for this signature's digest algorithm";
		} else {
			oid = wolfcrypt_rc;
		}
	}

	if (LLSEC_SUCCESS == result) {
		int wolfcrypt_rc = wc_EncodeSignature(out, digest, *digest_length, oid);
		LLSEC_SIG_DEBUG_TRACE("\t\twc_EncodeSignature(%p, %p, %d, %d) = %d\n", out, digest,
		                      *digest_length, oid, wolfcrypt_rc);
		if (wolfcrypt_rc < 0) {
			result = LLSEC_ERROR;
			*rc = LLSEC_ERROR_EXCEPTION;
			*error_code = wolfcrypt_rc;
		} else {
			*digest_length = wolfcrypt_rc;
		}
	}

	LLSEC_SIG_DEBUG_TRACE("\t\t=> SUCCESS (encoded length: %d)\n", *digest_length);
	return result;
}

static void LLSEC_SIG_IMPL_sign_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLSEC_SIG_DEBUG_TRACE("%s(%p)\n", __func__, job);
	LLSEC_SIG_sign_params_t *params = job->params;
	struct LLSEC_SIG_algorithm *algorithm = params->algorithm;
	const LLSEC_priv_key *priv_key = params->private_key;
	uint8_t *digest = params->digest;
	int32_t digest_length = params->digest_length;

	int32_t result = LLSEC_SUCCESS;

	if (LLSEC_SUCCESS == result) {
		if (priv_key->algo_type != algorithm->algo_type) {
			LLSEC_SIG_DEBUG_TRACE("\tcheck-failure: Key type does not match signature algorithm type\n");
			result = LLSEC_ERROR;
			params->rc = LLSEC_ERROR_EXCEPTION;
			params->error_code = LLSEC_ERROR;
			params->reason = "Private key not compatible with signature algorithm";
		}
	}

#ifndef NO_RSA
	// Workaround: https://github.com/wolfSSL/wolfssl/issues/5981
	uint8_t *encodedDigest = NULL;
	if (LLSEC_SUCCESS == result) {
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			encodedDigest = (uint8_t *)llsec_calloc(1, digest_length + MAX_DER_DIGEST_ASN_SZ);
			if (NULL == encodedDigest) {
				result = LLSEC_ERROR;
				params->rc = LLSEC_ERROR_EXCEPTION;
				params->error_code = LLSEC_ERROR_OOM;
				params->reason = "Could not allocate buffer to encode digest";
			}
		}
	}
	if (LLSEC_SUCCESS == result) {
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			result = llsec_sig_encodeDigestOid(encodedDigest, algorithm->hash_type, digest,
			                                   &digest_length, &params->rc,
			                                   &params->error_code, &params->reason);
		}
	}

	if (LLSEC_SUCCESS == result) {
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			digest = encodedDigest;
		}
	}
#endif // NO_RSA

	if (LLSEC_SUCCESS == result) {
		int wolfcrypt_rc = wc_SignatureGenerateHash_ex(algorithm->hash_type, algorithm->sig_type,
		                                               digest, digest_length,
		                                               params->signature, (word32 *)&params->signature_length,
		                                               params->private_key->any_key, algorithm->key_len,
		                                               llsec_wolfcrypt_RNG, 0);
		LLSEC_SIG_DEBUG_TRACE("\twc_SignatureGenerateHash(%d, %d, %p, %d, %p, %d, %p, %d, %p) = %d\n",
		                      algorithm->hash_type, algorithm->sig_type, digest, digest_length,
		                      params->signature, params->signature_length,
		                      params->private_key->any_key, algorithm->key_len, llsec_wolfcrypt_RNG,
		                      wolfcrypt_rc);
		if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
			params->rc = LLSEC_SUCCESS;
		} else {
			params->rc = LLSEC_ERROR_EXCEPTION;
			params->error_code = wolfcrypt_rc;
			params->reason = llsec_wc_error_message(wolfcrypt_rc);
		}
	}

#ifndef NO_RSA
	if (encodedDigest != NULL) {
		llsec_free(encodedDigest);
	}
#endif // NO_RSA

	LLSEC_SIG_DEBUG_TRACE("\t=> DONE\n");
}

static int32_t LLSEC_SIG_IMPL_sign_job_done(int32_t algorithm_id, uint8_t *signature, int32_t signature_length,
                                            int32_t private_key_id, uint8_t *digest, int32_t digest_length) {
	LLSEC_SIG_DEBUG_TRACE(
		"%s(algorithm_id=%d, signature=%p, signature_length=%d, private_key_id=%d, digest=%p, digest_length=%d)\n",
		__func__, algorithm_id, signature, signature_length, private_key_id, digest, digest_length);
	LLSEC_UNUSED_PARAM(algorithm_id);
	LLSEC_UNUSED_PARAM(signature_length);
	LLSEC_UNUSED_PARAM(private_key_id);
	LLSEC_UNUSED_PARAM(digest);
	LLSEC_UNUSED_PARAM(digest_length);

	int32_t return_code = 0;
	int32_t result = LLSEC_SUCCESS;

	MICROEJ_ASYNC_WORKER_job_t *job = NULL;
	if (result == LLSEC_SUCCESS) {
		job = MICROEJ_ASYNC_WORKER_get_job_done();
		if (job == NULL) {
			llsec_throw(LLSEC_ERROR, "Internal error: cannot retrieve async worker job done");
			result = LLSEC_ERROR_EXCEPTION;
		} else {
			LLSEC_SIG_DEBUG_TRACE("\tjob=%p\n", job);
		}
	}

	LLSEC_SIG_sign_params_t *params = NULL;
	if (result == LLSEC_SUCCESS) {
		params = (LLSEC_SIG_sign_params_t *)job->params;
		result = params->rc;

		switch (result) {
		case LLSEC_SUCCESS:
			return_code = params->signature_length;
			llsec_memcpy(signature, params->signature, params->signature_length);
			break;
		case LLSEC_ERROR_NOT_COMPLETED:
			LLSEC_ASSERT(("SNI callback executed before the async task has completed", false));
			llsec_throw(LLSEC_ERROR_NOT_COMPLETED, "Internal Error");
			return_code = SNI_IGNORED_RETURNED_VALUE;
			break;
		case LLSEC_ERROR_EXCEPTION:
		default:
			LLSEC_ASSERT(params->reason != NULL);
			if (params->reason == NULL) { // fallback if no assert
				params->reason = "Internal Error";
			}
			llsec_throw(params->error_code, params->reason);
			return_code = SNI_IGNORED_RETURNED_VALUE;
			break;
		}
	}

	if (params != NULL) {
		llsec_free(params->digest);
		llsec_free(params->signature);
	}

	if (job != NULL) {
		llsec_free_job(job);
	}

	LLSEC_SIG_DEBUG_TRACE("\t=> %d\n", return_code);
	return return_code;
}

static void LLSEC_SIG_IMPL_verify_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLSEC_SIG_DEBUG_TRACE("%s(%p)\n", __func__, job);

	LLSEC_SIG_verify_params_t *params = job->params;
	LLSEC_SIG_algorithm *algorithm = params->algorithm;
	const LLSEC_pub_key *pub_key = params->public_key;
	uint8_t *digest = params->digest;
	int32_t digest_length = params->digest_length;

	int32_t result = LLSEC_SUCCESS;

	if (LLSEC_SUCCESS == result) {
		if (pub_key->algo_type != algorithm->algo_type) {
			LLSEC_SIG_DEBUG_TRACE("\tcheck-failure: Key type does not match signature algorithm type\n");
			result = LLSEC_ERROR;
			params->rc = LLSEC_ERROR_EXCEPTION;
			params->error_code = LLSEC_ERROR;
			params->reason = "Public key not compatible with signature algorithm";
		}
	}

#ifndef NO_RSA
	// Workaround: https://github.com/wolfSSL/wolfssl/issues/5981
	uint8_t *encodedDigest = NULL;
	if (LLSEC_SUCCESS == result) {
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			encodedDigest = (uint8_t *)llsec_calloc(1, digest_length + MAX_DER_DIGEST_ASN_SZ);
			if (NULL == encodedDigest) {
				result = LLSEC_ERROR;
				params->rc = LLSEC_ERROR_EXCEPTION;
				params->error_code = LLSEC_ERROR_OOM;
				params->reason = "Could not allocate buffer to encode digest";
			}
		}
	}
	if (LLSEC_SUCCESS == result) {
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			result = llsec_sig_encodeDigestOid(encodedDigest, algorithm->hash_type, digest, &digest_length,
			                                   &params->rc, &params->error_code, &params->reason);
			digest = encodedDigest;
		}
	}
#endif // NO_RSA

	if (LLSEC_SUCCESS == result) {
		int wolfcrypt_rc = wc_SignatureVerifyHash(algorithm->hash_type, algorithm->sig_type,
		                                          digest, digest_length,
		                                          params->signature, params->signature_length,
		                                          params->public_key->any_key, algorithm->key_len);
		LLSEC_SIG_DEBUG_TRACE("\twc_SignatureVerifyHash(%d, %d, %p, %d, %p, %d, %p, %d) = %d\n",
		                      algorithm->hash_type, algorithm->sig_type, digest, digest_length,
		                      params->signature, params->signature_length,
		                      params->public_key->any_key, algorithm->key_len, wolfcrypt_rc);
		if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
			params->rc = LLSEC_SUCCESS;
		} else if (SIG_VERIFY_E == wolfcrypt_rc) {
			params->rc = LLSEC_ERROR;
		} else {
			params->rc = LLSEC_ERROR_EXCEPTION;
			params->error_code = wolfcrypt_rc;
			params->reason = llsec_wc_error_message(wolfcrypt_rc);
		}
	}

	LLSEC_SIG_DEBUG_TRACE("=> DONE\n");
}

static uint8_t LLSEC_SIG_IMPL_verify_job_done(int32_t algorithm_id, uint8_t *signature,
                                              int32_t signature_length, int32_t public_key_id,
                                              uint8_t *digest, int32_t digest_length) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_SIG_DEBUG_TRACE("%s(%p, %p, %d, %p, %p, %d)\n", __func__, (void *)algorithm_id, signature,
	                      signature_length, (void *)public_key_id, digest, digest_length);
	LLSEC_UNUSED_PARAM(algorithm_id);
	LLSEC_UNUSED_PARAM(signature);
	LLSEC_UNUSED_PARAM(signature_length);
	LLSEC_UNUSED_PARAM(public_key_id);
	LLSEC_UNUSED_PARAM(digest);
	LLSEC_UNUSED_PARAM(digest_length);

	int32_t result = LLSEC_SUCCESS;

	int8_t rc = JFALSE;

	MICROEJ_ASYNC_WORKER_job_t *job = NULL;
	if (result == LLSEC_SUCCESS) {
		job = MICROEJ_ASYNC_WORKER_get_job_done();
		if (job == NULL) {
			result = LLSEC_ERROR;
			llsec_throw(LLSEC_ERROR, "Internal error: cannot retrieve async worker job done");
		}
	}

	LLSEC_SIG_verify_params_t *params = NULL;
	if (result == LLSEC_SUCCESS) {
		params = (LLSEC_SIG_verify_params_t *)job->params;

		switch (params->rc) {
		case LLSEC_SUCCESS:
			rc = JTRUE;
			break;
		case LLSEC_ERROR:
			rc = JFALSE;
			break;
		case LLSEC_ERROR_NOT_COMPLETED:
			LLSEC_ASSERT(("SNI callback executed before the async task has completed", false));
			llsec_throw(LLSEC_ERROR_NOT_COMPLETED, "Internal Error");
			rc = SNI_IGNORED_RETURNED_VALUE;
			break;
		case LLSEC_ERROR_EXCEPTION:
		default:
			LLSEC_ASSERT(params->reason != NULL);
			if (params->reason == NULL) { // fallback if no assert
				params->reason = "Internal Error";
			}
			rc = SNI_IGNORED_RETURNED_VALUE;
			llsec_throw(params->error_code, params->reason);
			break;
		}
	}

	if (params != NULL) {
		llsec_free(params->digest);
		llsec_free(params->signature);
	}

	if (job != NULL) {
		llsec_free_job(job);
	}

	LLSEC_SIG_DEBUG_TRACE("\t=> %d\n", rc);
	return rc;
}

// --------------------------------------------------------------------------------
// LLSEC_KEY_FACTORY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_SIG_IMPL_get_algorithm_description(uint8_t *algorithm_name,
                                                 uint8_t *digest_algorithm_name,
                                                 int32_t digest_algorithm_name_length) {
	LLSEC_SIG_DEBUG_TRACE("%s(\"%s\", %p, %d)\n", __func__, algorithm_name, digest_algorithm_name,
	                      digest_algorithm_name_length);
	int32_t return_code = LLSEC_ERROR;

	int32_t nb_algorithms = sizeof(available_sig_algorithms) / sizeof(LLSEC_SIG_algorithm);
	LLSEC_SIG_algorithm *algorithm = &available_sig_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			llsec_strncpy(digest_algorithm_name, algorithm->digest_name, digest_algorithm_name_length);
			// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
			return_code = (int32_t)algorithm;
			break;
		}
		algorithm++;
	}

	LLSEC_SIG_DEBUG_TRACE("\t=> %d (digest algorithm: \"%s\")\n", return_code, digest_algorithm_name);
	return return_code;
}

// See the header file for the function documentation
void LLSEC_SIG_IMPL_get_algorithm_oid(uint8_t *algorithm_name, uint8_t *oid, int32_t oid_length) {
	LLSEC_SIG_DEBUG_TRACE("%s(\"%s\", %p, %d)\n", __func__, algorithm_name, oid, oid_length);

	int32_t nb_algorithms = sizeof(available_sig_algorithms) / sizeof(LLSEC_SIG_algorithm);
	LLSEC_SIG_algorithm *algorithm = &available_sig_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			llsec_strncpy(oid, algorithm->oid, oid_length);
			break;
		}
		algorithm++;
	}
	if (0 > nb_algorithms) {
		llsec_throw(LLSEC_ERROR, "Algorithm not found");
	}

	LLSEC_SIG_DEBUG_TRACE("\t=> oid: \"%s\"\n", oid);
}

// See the header file for the function documentation
int32_t LLSEC_SIG_IMPL_sign(int32_t algorithm_id, uint8_t *signature, int32_t signature_length,
                            int32_t private_key_id, uint8_t *digest, int32_t digest_length) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_SIG_DEBUG_TRACE("%s(%p, %p, %d, %p, %p, %d)\n", __func__, (void *)algorithm_id, signature,
	                      signature_length, (void *)private_key_id, digest, digest_length);
	LLSEC_UNUSED_PARAM(signature);
	int result = LLSEC_SUCCESS;

	MICROEJ_ASYNC_WORKER_job_t *job = NULL;
	if (result == LLSEC_SUCCESS) {
		job = llsec_allocate_job((SNI_callback)LLSEC_SIG_IMPL_sign);
		if (job == NULL) {
			result = LLSEC_ERROR;
			// MICROEJ_ASYNC_WORKER_allocate_job() has thrown a NativeException
		}
	}

	LLSEC_SIG_sign_params_t *params = NULL;
	if (result == LLSEC_SUCCESS) {
		params = job->params;

		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		params->algorithm = (LLSEC_SIG_algorithm *)algorithm_id;
		params->signature = NULL;
		params->signature_length = signature_length;
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		params->private_key = (LLSEC_priv_key *)private_key_id;
		params->digest = NULL;
		params->digest_length = digest_length;

		params->signature = llsec_calloc(1, signature_length);
		if (params->signature == NULL) {
			result = LLSEC_ERROR;
			llsec_throw(LLSEC_ERROR_OOM, "Cannot allocate signature buffer");
		}
	}

	if (result == LLSEC_SUCCESS) {
		params->digest = llsec_calloc(1, digest_length);
		if (params->digest != NULL) {
			llsec_memcpy(params->digest, digest, digest_length);
		} else {
			result = LLSEC_ERROR;
			llsec_throw(LLSEC_ERROR_OOM, "Cannot allocate digest buffer");
		}
	}

	if (result == LLSEC_SUCCESS) {
		params->rc = LLSEC_ERROR_NOT_COMPLETED;
		if (LLSEC_SUCCESS !=
		    llsec_async_exec(job, LLSEC_SIG_IMPL_sign_job, (SNI_callback)LLSEC_SIG_IMPL_sign_job_done)) {
			result = LLSEC_ERROR;
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
		}
	}

	if (result == LLSEC_ERROR) { // on error, free the allocated resources in reverse order
		if (params != NULL) {
			if (params->digest != NULL) {
				llsec_free(params->digest);
			}

			if (params->signature != NULL) {
				llsec_free(params->signature);
			}
		}

		if (job != NULL) {
			llsec_free_job(job);
		}
	}

	LLSEC_SIG_DEBUG_TRACE("=> DONE\n");
	return SNI_IGNORED_RETURNED_VALUE; // either successfully suspended with callback or exception thrown
}

// See the header file for the function documentation
uint8_t LLSEC_SIG_IMPL_verify(int32_t algorithm_id, uint8_t *signature, int32_t signature_length,
                              int32_t public_key_id, uint8_t *digest, int32_t digest_length) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_SIG_DEBUG_TRACE("%s(%p, %p, %d, %p, %p, %d)\n", __func__, (void *)algorithm_id, signature,
	                      signature_length, (void *)public_key_id, digest, digest_length);
	int result = LLSEC_SUCCESS;

	MICROEJ_ASYNC_WORKER_job_t *job = NULL;
	if (LLSEC_SUCCESS == result) {
		job = llsec_allocate_job((SNI_callback)LLSEC_SIG_IMPL_sign);
		if (job == NULL) {
			result = LLSEC_ERROR;
			// MICROEJ_ASYNC_WORKER_allocate_job() has thrown a NativeException
		}
	}

	LLSEC_SIG_verify_params_t *params = NULL;
	if (result == LLSEC_SUCCESS) {
		params = job->params;
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		params->algorithm = (LLSEC_SIG_algorithm *)algorithm_id;
		params->signature = NULL;
		params->signature_length = signature_length;
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		params->public_key = (LLSEC_pub_key *)public_key_id;
		params->digest = NULL;
		params->digest_length = digest_length;

		params->signature = llsec_calloc(1, signature_length);
		if (params->signature != NULL) {
			llsec_memcpy(params->signature, signature, signature_length);
		} else {
			result = LLSEC_ERROR;
			llsec_throw(LLSEC_ERROR, "Cannot allocate signature buffer");
		}
	}

	if (result == LLSEC_SUCCESS) {
		params->digest = llsec_calloc(1, digest_length);
		if (params->digest != NULL) {
			llsec_memcpy(params->digest, digest, digest_length);
		} else {
			result = LLSEC_ERROR;
			llsec_throw(LLSEC_ERROR, "Cannot allocate digest buffer");
		}
	}

	if (result == LLSEC_SUCCESS) {
		params->rc = LLSEC_ERROR_NOT_COMPLETED;
		if (LLSEC_SUCCESS !=
		    llsec_async_exec(job, LLSEC_SIG_IMPL_verify_job, (SNI_callback)LLSEC_SIG_IMPL_verify_job_done)) {
			result = LLSEC_ERROR;
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
		}
	}

	if (result != LLSEC_SUCCESS) { // on error, free the allocated resources in reverse order
		if (params != NULL) {
			if (params->digest != NULL) {
				llsec_free(params->digest);
			}
			if (params->signature != NULL) {
				llsec_free(params->signature);
			}
		}
		if (job != NULL) {
			llsec_free_job(job);
		}
	}

	LLSEC_SIG_DEBUG_TRACE("=> DONE\n");
	return SNI_IGNORED_RETURNED_VALUE; // either successfully suspended with callback or exception thrown
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
