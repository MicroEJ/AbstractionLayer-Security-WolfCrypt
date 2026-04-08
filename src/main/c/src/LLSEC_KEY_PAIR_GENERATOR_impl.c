/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Key pair generators.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_common.h>
#include <LLSEC_ERRORS.h>
#include <LLSEC_KEY_PAIR_GENERATOR_impl.h>

#include <sni.h>
#include <string.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef void (*LLSEC_KEY_PAIR_GENERATOR_close)(void *native_id);

struct LLSEC_KEY_PAIR_GENERATOR_algorithm {
	char *name;
	LLSEC_KEY_PAIR_GENERATOR_close close;
};

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static void LLSEC_KEY_PAIR_GENERATOR_IMPL_rsa_close(void *native_id) {
	LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE("%s(key=%p)\n", __func__, native_id);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_key *key = (LLSEC_key *)native_id;
	llsec_wolfcrypt_rsa_free(key);
	llsec_free(key);
}

static void LLSEC_KEY_PAIR_GENERATOR_IMPL_ec_close(void *native_id) {
	LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE("%s(key=%p)\n", __func__, native_id);
	// cppcheck-suppress [misra-c2012-11.5] : Abstract data type for SNI usage
	LLSEC_priv_key *key = (LLSEC_priv_key *)native_id;
	llsec_wolfcrypt_ec_free(key);
	llsec_free(key);
}

// --------------------------------------------------------------------------------
// LLSEC_KEY_PAIR_GENERATOR_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_KEY_PAIR_GENERATOR_IMPL_get_algorithm(uint8_t *algorithm_name) {
	LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE("%s \n", __func__);
	int32_t result = LLSEC_ERROR;

	static LLSEC_KEY_PAIR_GENERATOR_algorithm supported_algorithms[] = {
#ifndef NO_RSA
		{
			.name = "RSA",
			.close = LLSEC_KEY_PAIR_GENERATOR_IMPL_rsa_close
		},
#endif // NO_RSA
#ifdef HAVE_ECC
		{
			.name = "EC",
			.close = LLSEC_KEY_PAIR_GENERATOR_IMPL_ec_close
		}
#endif // HAVE_ECC
	};

	int32_t nb_algorithms = sizeof(supported_algorithms) / sizeof(LLSEC_KEY_PAIR_GENERATOR_algorithm);
	LLSEC_KEY_PAIR_GENERATOR_algorithm *algorithm = &supported_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			break;
		}
		algorithm++;
	}

	if (0 <= nb_algorithms) {
		// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
		result = (int32_t)algorithm;
	}
	return result;
}

static void LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_params_t *params =
		(LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_params_t *)job->params;
	const LLSEC_KEY_PAIR_GENERATOR_algorithm *algorithm = params->algorithm;

	// assume the key generation will succeed to handle fail case in a single place
	params->rc = LLSEC_SUCCESS;
	params->reason = NULL;

#ifndef NO_RSA
	if (0 == strcmp(algorithm->name, "RSA")) {
		params->rc = llsec_wolfcrypt_rsa_generate_key_pair(params->key, params->rsa_key_size,
		                                                   params->rsa_public_exponent,
		                                                   &params->wolfcrypt_rc, &params->reason);
	} else
#endif // NO_RSA
#ifdef HAVE_ECC
	if (0 == strcmp(algorithm->name, "EC")) {
		params->rc = llsec_wolfcrypt_ec_generate_key_pair(params->key, (uint8_t *)params->ec_curve_stdname,
		                                                  &params->wolfcrypt_rc, &params->reason);
	} else
#endif // HAVE_ECC
	{
		// Algorithm not found error.
		// This should never happen because the algorithm_id is a valid algorithm at this level.
		params->rc = LLSEC_ERROR;
		params->reason = "Internal error: invalid algorithm";
	}
}

static int32_t LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_job_done(int32_t algorithm_id,
                                                                 int32_t rsa_key_size,
                                                                 int32_t rsa_public_exponent,
                                                                 uint8_t *ec_curve_stdname) {
	LLSEC_UNUSED_PARAM(algorithm_id);
	LLSEC_UNUSED_PARAM(rsa_key_size);
	LLSEC_UNUSED_PARAM(rsa_public_exponent);
	LLSEC_UNUSED_PARAM(ec_curve_stdname);

	int32_t result = LLSEC_SUCCESS;
	const char *reason = NULL;

	MICROEJ_ASYNC_WORKER_job_t *job = MICROEJ_ASYNC_WORKER_get_job_done();
	if (job == NULL) {
		result = LLSEC_ERROR;
		reason = "Internal error: cannot retrieve async worker job done";
	}

	LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_params_t *params = NULL;
	const LLSEC_KEY_PAIR_GENERATOR_algorithm *algorithm = NULL;
	if (result == LLSEC_SUCCESS) {
		params = (LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_params_t *)job->params;
		algorithm = params->algorithm;
		// retrieve returned code from job
		result = params->rc;
		reason = params->reason;
	}

	// register close if the key was allocated
	if (result == LLSEC_SUCCESS) {
		// cppcheck-suppress [misra-c2012-11.8]: The SNI API does not use the const keyword.
		if (SNI_OK != SNI_registerResource(params->key, algorithm->close, NULL)) {
			// free allocated memory if the resource cannot be registered
			algorithm->close(params->key);
			result = LLSEC_ERROR;
			reason = "Internal error: cannot register native resource";
		}
	}

	switch (result) {
	case LLSEC_SUCCESS:
	{
		result = (int32_t)params->key;
		break;
	}
	case LLSEC_ERROR_EXCEPTION:
	{
		llsec_throw(params->wolfcrypt_rc, reason);
		result = SNI_IGNORED_RETURNED_VALUE;
		break;
	}
	default:
	{
		llsec_throw(result, reason);
		result = SNI_IGNORED_RETURNED_VALUE;
	}
	}

	if (job != NULL) {
		llsec_free_job(job);
	}

	return result;
}

// See the header file for the function documentation
int32_t LLSEC_KEY_PAIR_GENERATOR_IMPL_generateKeyPair(int32_t algorithm_id, int32_t rsa_key_size,
                                                      int32_t rsa_public_exponent, uint8_t *ec_curve_stdname) {
	LLSEC_KEY_PAIR_GENERATOR_DEBUG_TRACE("%s(alg=%d, rsa_key_size=%d, rsa_public_exponent=%d, ec_curve_stdname=%s)\n",
	                                     __func__, algorithm_id, rsa_key_size, rsa_public_exponent,
	                                     ec_curve_stdname);
	int32_t result = LLSEC_SUCCESS;

	MICROEJ_ASYNC_WORKER_job_t *job = MICROEJ_ASYNC_WORKER_allocate_job(&llsec_worker,
	                                                                    (SNI_callback)
	                                                                    LLSEC_KEY_PAIR_GENERATOR_IMPL_generateKeyPair);
	if (job == NULL) {
		// MICROEJ_ASYNC_WORKER_allocate_job() has thrown a NativeException
		result = LLSEC_ERROR;
	}

	LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_params_t *params = NULL;
	if (result == LLSEC_SUCCESS) {
		params = (LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_params_t *)job->params;
		params->key = (LLSEC_key_pair *)llsec_calloc(1, sizeof(LLSEC_key_pair));
		if (params->key == NULL) {
			llsec_throw(SNI_ERROR, "failed to allocate keypair context");
			result = LLSEC_ERROR;
		}
	}

	if (result == LLSEC_SUCCESS) {
		int rc;
		uint32_t discarded;
		params->algorithm = (LLSEC_KEY_PAIR_GENERATOR_algorithm *)algorithm_id;
		params->rsa_key_size = rsa_key_size;
		params->rsa_public_exponent = rsa_public_exponent;

		rc = SNI_retrieveArrayElements((jbyte *)ec_curve_stdname, 0,
		                               SNI_getArrayLength(ec_curve_stdname),
		                               (int8_t *)params->ec_curve_stdname_buffer,
		                               sizeof(params->ec_curve_stdname_buffer),
		                               (int8_t **)&params->ec_curve_stdname, &discarded, true);
		if (rc != SNI_OK) {
			llsec_throw(rc, "SNI_retrieveArrayElements() failed");
			result = LLSEC_ERROR;
		}
	}

	if (result == LLSEC_SUCCESS) {
		int32_t rc = llsec_async_exec(job,
		                              LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_job,
		                              (SNI_callback)LLSEC_KEY_PAIR_GENERATOR_generateKeyPair_job_done);
		if (rc != LLSEC_SUCCESS) {
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
			result = LLSEC_ERROR;
		}
	}

	if (result != LLSEC_SUCCESS) {
		if (params->key != NULL) {
			llsec_free(params->key);
		}
		if (job != NULL) {
			llsec_free_job(job);
		}
	}

	// Either the thread was successfully suspended, or an error happened and an exception will be
	// thrown
	return SNI_IGNORED_RETURNED_VALUE;
}

// See the header file for the function documentation
int32_t LLSEC_KEY_PAIR_GENERATOR_IMPL_get_close_id(int32_t algorithm_id) {
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_KEY_PAIR_GENERATOR_algorithm *algorithm = (LLSEC_KEY_PAIR_GENERATOR_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.1] : Abstract data type for SNI usage
	return (int32_t)algorithm->close;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
