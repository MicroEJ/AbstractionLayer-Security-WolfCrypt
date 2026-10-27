/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - Private key PKCS8 encoding.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_ERRORS.h>
#include <LLCRYPTO_PRIVATE_KEY_impl.h>
#include <LLCRYPTO_wolfcrypt.h>
#include <LLCRYPTO_common.h>
#include "microej_async_worker.h"

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

/**
 * @brief Provides the size of the input ECC key in the PKCS8 format.
 *
 * @param[in] ecc_key ECC key pointer targeting the input key.
 *
 * @return Returns the ECC key size in PKCS8 format on success, else <code>LLCRYPTO_ERROR</code> is returned.
 */
static int llcrypto_pkcs8_get_size_ec(ecc_key *ecc_key) {
	int ret = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc;

	// Get the size of the EC DER
	word32 der_size;
	if (ret == LLCRYPTO_SUCCESS) {
		wolfcrypt_rc = wc_BuildEccKeyDer(ecc_key, NULL, &der_size, 0, // 0 == private key only
		                                 0); // 0 == no curve name (it will be added to the PKCS8 header)
		LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("\twc_BuildEccKeyDer(%p, NULL, %p, %d, %d) = %d\n", ecc_key, &der_size, 0, 0,
		                                 wolfcrypt_rc);
		if (wolfcrypt_rc != LENGTH_ONLY_E) {
			LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("wc_BuildEccKeyDer error %d: %s\n",
			                                 wolfcrypt_rc, wc_GetErrorString(wolfcrypt_rc));
			ret = LLCRYPTO_ERROR;
		}
	}

	// Get the size of the algorithm OID
	byte const *oid;
	word32 oid_size;
	if (ret == LLCRYPTO_SUCCESS) {
		wolfcrypt_rc = wc_ecc_get_oid(ecc_key->dp->oidSum, &oid, &oid_size);
		LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("\twc_ecc_get_oid(%d, %p, %p) = %d\n", ecc_key->dp->oidSum, &oid,
		                                 &oid_size, wolfcrypt_rc);
		if (wolfcrypt_rc < 0) {
			llcrypto_throw(wolfcrypt_rc, wc_GetErrorString(wolfcrypt_rc));
			ret = LLCRYPTO_ERROR;
		}
	}

	// Get the total size of the PKCS8
	word32 pkcs8_size;
	if (ret == LLCRYPTO_SUCCESS) {
		wolfcrypt_rc = wc_CreatePKCS8Key(NULL, &pkcs8_size, NULL, der_size, ECDSAk, oid, oid_size);
		LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("\twc_CreatePKCS8Key(NULL, %p, NULL, %d, %d, %p, %d) = %d\n", &pkcs8_size,
		                                 der_size, ECDSAk, oid, oid_size, wolfcrypt_rc);
		if (wolfcrypt_rc != LENGTH_ONLY_E) {
			llcrypto_throw(wolfcrypt_rc, wc_GetErrorString(wolfcrypt_rc));
			ret = LLCRYPTO_ERROR;
		}
	}

	return ret == LLCRYPTO_SUCCESS ? pkcs8_size : SNI_IGNORED_RETURNED_VALUE;
}

/**
 * @brief Encodes the given ECC key into the PKCS8 format.
 *
 * @param[in] ecc_key ECC key pointer targeting the input key.
 * @param[out] pkcs8 Byte array to store the ECC key in the PKCS8 format.
 * @param[in] pkcs8_size Size of the given output byte array.
 *
 * @return Returns the ECC key size in PKCS8 format on success, else <code>LLCRYPTO_ERROR</code> is returned.
 */
static int llcrypto_pkcs8_encode_ec(ecc_key *ecc_key, byte *pkcs8, word32 pkcs8_size) {
	int ret = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc;

	// Get the size of the EC DER
	word32 der_size;
	if (ret == LLCRYPTO_SUCCESS) {
		wolfcrypt_rc = wc_BuildEccKeyDer(ecc_key, NULL, &der_size, 0, // 0 == private key only
		                                 0); // 0 == no curve name (it will be added to the PKCS8 header)
		LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("\twc_BuildEccKeyDer(%p, NULL, %p, %d, %d) = %d\n",
		                                 ecc_key, &der_size, 0, 0, wolfcrypt_rc);
		if (wolfcrypt_rc != LENGTH_ONLY_E) {
			llcrypto_throw(wolfcrypt_rc, wc_GetErrorString(wolfcrypt_rc));
			ret = LLCRYPTO_ERROR;
		}
	}

	// Allocate buffer to encode the EC DER
	byte *der = NULL;
	if (ret == LLCRYPTO_SUCCESS) {
		der = (byte *)llcrypto_calloc(1, der_size);
		if (der == NULL) {
			llcrypto_throw(LLCRYPTO_ERROR_OOM, "Could not allocate DER buffer for encoding");
			ret = LLCRYPTO_ERROR;
		}
	}

	// Encode to EC DER
	if (ret == LLCRYPTO_SUCCESS) {
		wolfcrypt_rc = wc_BuildEccKeyDer(ecc_key, der, &der_size, 0, // 0 == private key only
		                                 0); // 0 == no curve name (it will be added to the PKCS8 header)
		LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("\twc_BuildEccKeyDer(%p, %p, %p, %d, %d) = %d\n", ecc_key, der,
		                                 &der_size, 0, 0, wolfcrypt_rc);
		if (wolfcrypt_rc < 0) {
			llcrypto_throw(wolfcrypt_rc, wc_GetErrorString(wolfcrypt_rc));
			ret = LLCRYPTO_ERROR;
		} else {
			der_size = wolfcrypt_rc; // actual size after encoding
		}
	}

	// Get the algorithm OID
	byte const *oid;
	word32 oid_size;
	if (ret == LLCRYPTO_SUCCESS) {
		wolfcrypt_rc = wc_ecc_get_oid(ecc_key->dp->oidSum, &oid, &oid_size);
		LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("\twc_ecc_get_oid(%d, %p, %p) = %d\n", ecc_key->dp->oidSum, &oid,
		                                 &oid_size, wolfcrypt_rc);
		if (wolfcrypt_rc < 0) {
			llcrypto_throw(wolfcrypt_rc, wc_GetErrorString(wolfcrypt_rc));
			ret = LLCRYPTO_ERROR;
		}
	}

	// Encode to PKCS8
	if (ret == LLCRYPTO_SUCCESS) {
		wolfcrypt_rc = wc_CreatePKCS8Key(pkcs8, &pkcs8_size, der, der_size, ECDSAk, oid, oid_size);
		LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("\twc_CreatePKCS8Key(%p, %p, %p, %d, %d, %p, %d) = %d\n", pkcs8,
		                                 &pkcs8_size, der, der_size, ECDSAk, oid, oid_size, wolfcrypt_rc);
		if (wolfcrypt_rc < 0) {
			llcrypto_throw(wolfcrypt_rc, wc_GetErrorString(wolfcrypt_rc));
			ret = LLCRYPTO_ERROR;
		}
	}

	// Cleanup
	if (der != NULL) {
		llcrypto_free(der);
	}
	return (ret == LLCRYPTO_SUCCESS) ? pkcs8_size : LLCRYPTO_ERROR;
}

// -----------------------------------------------------------------------------
// LLCRYPTO_PRIVATE_KEY*_on_done functions
// -----------------------------------------------------------------------------

jint LLCRYPTO_PRIVATE_KEY_IMPL_get_encode_on_done(int32_t native_id, uint8_t *output, int32_t outputLength) {
	LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("%s\n", __func__);
	MICROEJ_ASYNC_WORKER_job_t *job = MICROEJ_ASYNC_WORKER_get_job_done();
	LLCRYPTO_PRIVATE_KEY_get_encoded_params_t *params = (LLCRYPTO_PRIVATE_KEY_get_encoded_params_t *)job->params;

	// Parameters unused but mandatory to have the same signature than the original native.
	LLCRYPTO_UNUSED_PARAM(native_id);

	// The given error_code is the real key size that must be positive.
	if (params->error_code > 0) {
		if (SNI_OK != SNI_flushArrayElements((jbyte *)output, 0, outputLength, (int8_t *)params->output,
		                                     params->error_code)) {
			llcrypto_throw(LLCRYPTO_ERROR, "SNI_flushArrayElements: Internal error");
		} else {
			// Nothing to do, the copy to the Java has been completed.
		}
	}

	if (params->error_code != LLCRYPTO_ERROR_OOM) {
		if (NULL != params->output) {
			llcrypto_free(params->output);
		}
	} else {
		// Returns the generic error code, LLCRYPTO_ERROR_OOM use is internal of this native.
		params->error_code = LLCRYPTO_ERROR;
	}

	llcrypto_free_job(job);
	LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("%s (result=%d) \n", __func__, params->error_code);
	return (jint)params->error_code;
}

// -----------------------------------------------------------------------------
// LLCRYPTO_PRIVATE_KEY*_action functions
// -----------------------------------------------------------------------------

void LLCRYPTO_PRIVATE_KEY_IMPL_get_encode_action(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("%s\n", __func__);
	LLCRYPTO_PRIVATE_KEY_get_encoded_params_t *params = (LLCRYPTO_PRIVATE_KEY_get_encoded_params_t *)job->params;

	LLCRYPTO_priv_key *key = params->key;
	int32_t output_length = params->output_length;

	params->output = llcrypto_calloc(output_length, sizeof(uint8_t));
	if (NULL != params->output) {
		switch (key->algo_type) {
#ifndef NO_RSA
		case ALGO_RSA:
		{
			int wolfcrypt_rc = wc_RsaKeyToDer(key->rsa_key, params->output, output_length);
			if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
				LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("wc_RsaKeyToDer() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
				params->error_code = LLCRYPTO_ERROR;
			} else {
				params->error_code = wolfcrypt_rc;
			}
			break;
		}
#endif // NO_RSA
		case ALGO_ECDSA:
			if (NULL != key->ec_key->dp) {
				params->error_code = llcrypto_pkcs8_encode_ec(key->ec_key, params->output, output_length);
			} else {
				llcrypto_throw(LLCRYPTO_ERROR, "Key no retrievable");
			}
			break;
		default:
			// it should never happen
			break;
		}
	} else {
		LLCRYPTO_EXTERNAL_KEYSTORE_DEBUG_TRACE("Could not allocate the key buffer\n");
		params->error_code = LLCRYPTO_ERROR_OOM;
	}
}

// --------------------------------------------------------------------------------
// LLCRYPTO_PRIVATE_KEY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLCRYPTO_PRIVATE_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("%s(%p)\n", __func__, (void *)native_id);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_priv_key *key = (LLCRYPTO_priv_key *)native_id;

	int return_code = LLCRYPTO_ERROR;

	switch (key->algo_type) {
#ifndef NO_RSA
	case ALGO_RSA:
		return_code = 8 * (RSA_MAX_SIZE / 8);
		break;
#endif // NO_RSA
	case ALGO_ECDSA:
		if (NULL != key->ec_key->dp) {
			return_code = llcrypto_pkcs8_get_size_ec(key->ec_key);
		} else {
			llcrypto_throw(LLCRYPTO_ERROR, "Key no retrievable");
		}
		break;
	default:
		return_code = LLCRYPTO_ERROR;     // it should never happen
		break;
	}
	LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("%s() => %d\n", __func__, return_code);
	return return_code;
}

// See the header file for the function documentation
// cppcheck-suppress [misra-c2012-2.7] : false positive, parameters used in optional debug trace.
int32_t LLCRYPTO_PRIVATE_KEY_IMPL_get_encode(int32_t native_id, uint8_t *output, int32_t outputLength) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("%s(%p, %p, %d)\n", __func__, (void *)native_id, output, outputLength);

	jint result = LLCRYPTO_SUCCESS;
	MICROEJ_ASYNC_WORKER_job_t *job =
		MICROEJ_ASYNC_WORKER_allocate_job(&llcrypto_worker, (SNI_callback)LLCRYPTO_PRIVATE_KEY_IMPL_get_encode);
	if (job == NULL) {
		// No job available, either:
		// - wait for a job to be available and this function to be executed again,
		// - or an exception is pending
		result = LLCRYPTO_JOB_UNAVAILABLE;
	}

	if (LLCRYPTO_SUCCESS == result) {
		LLCRYPTO_PRIVATE_KEY_get_encoded_params_t *params = (LLCRYPTO_PRIVATE_KEY_get_encoded_params_t *)job->params;

		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		params->key = (LLCRYPTO_priv_key *)native_id;
		params->output_length = outputLength;
	}

	if (LLCRYPTO_SUCCESS == result) {
		int32_t status = llcrypto_async_exec(job,
		                                     LLCRYPTO_PRIVATE_KEY_IMPL_get_encode_action,
		                                     (SNI_callback)LLCRYPTO_PRIVATE_KEY_IMPL_get_encode_on_done);
		if (status == LLCRYPTO_SUCCESS) {
			// Wait for the action to be done
			result = SNI_IGNORED_RETURNED_VALUE; //returned value not used
		} else {
			// An error occurred and MICROEJ_ASYNC_WORKER_async_exec has thrown a SNI exception
			// and the job must be released explicitly.
			result = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_ERROR == result) {
		// Release the job when an error occured when the job has been allocated.
		llcrypto_free_job(job);
	} else if (LLCRYPTO_JOB_UNAVAILABLE == result) {
		// The Java thread is suspended until a job is available, or a NativeException is pending: the returned
		// value is ignored and must not be mistaken for a LLCRYPTO_CONSTANTS.h code.
		result = SNI_IGNORED_RETURNED_VALUE;
	} else {
		// Nothing to do: the result is returned as is.
	}

	return result;
}

// See the header file for the function documentation
int32_t LLCRYPTO_PRIVATE_KEY_IMPL_get_output_size(int32_t native_id) {
	LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("%s\n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_pub_key *key = (LLCRYPTO_pub_key *)native_id;

	int return_code = LLCRYPTO_ERROR;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;

	switch (key->algo_type) {
#ifndef NO_RSA
	case ALGO_RSA:
		wolfcrypt_rc = wc_RsaEncryptSize(key->rsa_key);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
			LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("wc_RsaEncryptSize() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
			llcrypto_throw(wolfcrypt_rc, "Output buffer size get failed");
		} else {
			return_code = wolfcrypt_rc;
		}
		break;
#endif // NO_RSA
	case ALGO_ECDSA:
		if (NULL != key->ec_key->dp) {
			wolfcrypt_rc = wc_ecc_sig_size(key->ec_key);
			if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
				LLCRYPTO_PRIVATE_KEY_DEBUG_TRACE("wc_ecc_sig_size() failed: %s\n", wc_GetErrorString(wolfcrypt_rc));
				llcrypto_throw(wolfcrypt_rc, "Output buffer size get failed");
			} else {
				return_code = wolfcrypt_rc;
			}
		} else {
			llcrypto_throw(LLCRYPTO_ERROR, "Key no retrievable");
		}
		break;
	default:
		// it should never happen
		break;
	}
	return return_code;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
