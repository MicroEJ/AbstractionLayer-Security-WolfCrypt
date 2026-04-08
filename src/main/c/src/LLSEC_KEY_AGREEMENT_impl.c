/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Key Agreement (ECDH)
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_KEY_AGREEMENT_impl.h>
#include <LLSEC_ERRORS.h>
#include <LLSEC_common.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static void LLSEC_KEY_AGREEMENT_IMPL_generate_secret_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLSEC_KEY_AGREEMENT_DEBUG_TRACE("%s\n", __func__);
	LLSEC_KEY_AGREEMENT_generate_secret_params_t *params =
		(LLSEC_KEY_AGREEMENT_generate_secret_params_t *)job->params;
	ecc_key *private_key = params->priv_key->ec_key;
	ecc_key *public_key = params->pub_key->ec_key;
	byte *secret_buffer = (byte *)params->secret_buffer;
	word32 secretSz = LLSEC_KEY_AGREEMENT_MAX_SECRET_SIZE;
	int wc_ret = wc_ecc_shared_secret(private_key, public_key, secret_buffer, &secretSz);
	if (LLSEC_WOLFCRYPT_SUCCESS == wc_ret) {
		params->rc = LLSEC_SUCCESS;
		params->secret_size = secretSz;
	} else if (ECC_BAD_ARG_E == wc_ret) {
		params->rc = LLSEC_ERROR;
	} else if (MEMORY_E == wc_ret) {
		params->rc = LLSEC_ERROR_OOM;
	} else {
		params->rc = LLSEC_ERROR_EXCEPTION;
		params->wolfcrypt_rc = wc_ret;
	}
	LLSEC_KEY_AGREEMENT_DEBUG_TRACE("%s (rc=%d ; secret_size=%d ; wolfcrypt_rc=0x%p ; secret_buffer=0x%x)\n", __func__,
	                                params->rc, params->secret_size, params->wolfcrypt_rc, params->secret_buffer);
}

static int32_t LLSEC_KEY_AGREEMENT_IMPL_generate_secret_job_done(int32_t algorithm, int32_t local_private_key,
                                                                 int32_t remote_public_key, uint8_t *secret_buffer) {
	LLSEC_KEY_AGREEMENT_DEBUG_TRACE("%s\n", __func__);
	LLSEC_UNUSED_PARAM(algorithm);
	LLSEC_UNUSED_PARAM(local_private_key);
	LLSEC_UNUSED_PARAM(remote_public_key);

	int32_t result = LLSEC_SUCCESS;
	MICROEJ_ASYNC_WORKER_job_t *job;
	if (LLSEC_SUCCESS == result) {
		job = MICROEJ_ASYNC_WORKER_get_job_done();
		if (job == NULL) {
			result = LLSEC_ERROR;
			llsec_throw(LLSEC_ERROR, "Internal error: cannot retrieve async worker job done");
		}
	}
	if (LLSEC_SUCCESS == result) {
		LLSEC_KEY_AGREEMENT_generate_secret_params_t *params =
			(LLSEC_KEY_AGREEMENT_generate_secret_params_t *)job->params;
		result = params->rc;
		if (LLSEC_SUCCESS == result) {
			llsec_memcpy(secret_buffer, params->secret_buffer, params->secret_size);
			(void)memset(params->secret_buffer, 0, params->secret_size);
			result = params->secret_size;
		} else if (LLSEC_ERROR_EXCEPTION == result) {
			llsec_throw(params->wolfcrypt_rc, llsec_wc_error_message(params->wolfcrypt_rc));
			result = LLSEC_ERROR;
		} else {
			// Nothing to do, the error code is returned without exception in this case.
		}
	}
	if (job != NULL) {
		llsec_free_job(job);
	}
	LLSEC_KEY_AGREEMENT_DEBUG_TRACE("%s (result=%d ; secret_buffer=0x%x)\n", __func__, result, secret_buffer);
	return result;
}

// --------------------------------------------------------------------------------
// LLSEC_KEY_AGREEMENT_impl.h functions
// --------------------------------------------------------------------------------

// see LLSEC_KEY_AGREEMENT_impl.h
int32_t LLSEC_KEY_AGREEMENT_IMPL_get_algorithm_id(uint8_t *algorithm_name) {
	LLSEC_KEY_AGREEMENT_DEBUG_TRACE("%s(algorithm=\"%s\")\n", __func__, algorithm_name);
	return (strcmp("ECDH", (const char *)algorithm_name) == 0) ? 0 : LLSEC_ERROR;
}

// see LLSEC_KEY_AGREEMENT_impl.h
// cppcheck-suppress [misra-c2012-2.7] : false positive, parameters used in optional debug trace and available for other
// implemenations.
int32_t LLSEC_KEY_AGREEMENT_IMPL_get_max_size(int32_t algorithm, int32_t local_private_key, int32_t remote_public_key) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_KEY_AGREEMENT_DEBUG_TRACE("%s(priv_key=0x%p, public_key=0x%p)\n", __func__, (void *)local_private_key,
	                                (void *)remote_public_key);
	int32_t result = 0;
	if (algorithm != 0) {
		llsec_throw(algorithm, "Internal error: invalid algorithm");
	} else {
		result = 1024; // maybe could be optimized using private_key->dp?
	}
	return result;
}

// see LLSEC_KEY_AGREEMENT_impl.h
int32_t LLSEC_KEY_AGREEMENT_IMPL_generate_secret(int32_t algorithm, int32_t local_private_key,
                                                 int32_t remote_public_key, uint8_t *secret_buffer) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_KEY_AGREEMENT_DEBUG_TRACE("%s(priv_key=0x%p, public_key=0x%p)\n", __func__, (void *)local_private_key,
	                                (void *)remote_public_key);
	LLSEC_UNUSED_PARAM(secret_buffer);
	int32_t result = LLSEC_SUCCESS;

	if (algorithm != 0) {
		llsec_throw(algorithm, "Internal error: invalid algorithm");
		result = LLSEC_ERROR;
	}
	LLSEC_priv_key *priv_key = (LLSEC_priv_key *)local_private_key;
	LLSEC_pub_key *pub_key = (LLSEC_pub_key *)remote_public_key;
	if ((priv_key->algo_type != ALGO_ECDSA) || (pub_key->algo_type != ALGO_ECDSA)) {
		result = LLSEC_ERROR;
	}

	MICROEJ_ASYNC_WORKER_job_t *job = NULL;
	if (result == LLSEC_SUCCESS) {
		job = MICROEJ_ASYNC_WORKER_allocate_job(&llsec_worker,
		                                        (SNI_callback)LLSEC_KEY_AGREEMENT_IMPL_generate_secret);
		if (job == NULL) {
			result = LLSEC_ERROR;
			// MICROEJ_ASYNC_WORKER_allocate_job() has thrown a NativeException
		}
	}

	LLSEC_KEY_AGREEMENT_generate_secret_params_t *params = NULL;
	if (result == LLSEC_SUCCESS) {
		params = (LLSEC_KEY_AGREEMENT_generate_secret_params_t *)job->params;
		params->priv_key = priv_key;
		params->pub_key = pub_key;
		int32_t rc = llsec_async_exec(job,
		                              LLSEC_KEY_AGREEMENT_IMPL_generate_secret_job,
		                              (SNI_callback)LLSEC_KEY_AGREEMENT_IMPL_generate_secret_job_done);
		if (rc != LLSEC_SUCCESS) {
			result = LLSEC_ERROR;
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
		}
	}

	if (result != LLSEC_SUCCESS) {
		if (job != NULL) {
			llsec_free_job(job);
		}
	}

	return result;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
