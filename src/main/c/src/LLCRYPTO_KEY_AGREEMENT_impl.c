/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - Key Agreement (ECDH)
 * @author MicroEJ Developer Team
 * @version 2.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_KEY_AGREEMENT_impl.h>
#include <LLCRYPTO_ERRORS.h>
#include <LLCRYPTO_common.h>
#include <wolfssl/wolfcrypt/memory.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static void LLCRYPTO_KEY_AGREEMENT_IMPL_generate_secret_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE("%s\n", __func__);
	LLCRYPTO_KEY_AGREEMENT_generate_secret_params_t *params =
		(LLCRYPTO_KEY_AGREEMENT_generate_secret_params_t *)job->params;
	ecc_key *private_key = params->priv_key->ec_key;
	ecc_key *public_key = params->pub_key->ec_key;
	byte *secret_buffer = (byte *)params->secret_buffer;
	word32 secretSz = LLCRYPTO_KEY_AGREEMENT_MAX_SECRET_SIZE;
	int wc_ret = wc_ecc_shared_secret(private_key, public_key, secret_buffer, &secretSz);
	if (LLCRYPTO_WOLFCRYPT_SUCCESS == wc_ret) {
		params->rc = LLCRYPTO_SUCCESS;
		params->secret_size = secretSz;
	} else if (ECC_BAD_ARG_E == wc_ret) {
		params->rc = LLCRYPTO_ERROR;
	} else if (MEMORY_E == wc_ret) {
		params->rc = LLCRYPTO_ERROR_OOM;
	} else {
		params->rc = LLCRYPTO_JOB_EXCEPTION;
		params->wolfcrypt_rc = wc_ret;
	}
	LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE("%s (rc=%d ; secret_size=%d ; wolfcrypt_rc=0x%p ; secret_buffer=0x%x)\n",
	                                   __func__,
	                                   params->rc, params->secret_size, params->wolfcrypt_rc, params->secret_buffer);
}

static int32_t LLCRYPTO_KEY_AGREEMENT_IMPL_generate_secret_job_done(int32_t algorithm, int32_t local_private_key,
                                                                    int32_t remote_public_key, uint8_t *secret_buffer) {
	LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE("%s\n", __func__);
	LLCRYPTO_UNUSED_PARAM(algorithm);
	LLCRYPTO_UNUSED_PARAM(local_private_key);
	LLCRYPTO_UNUSED_PARAM(remote_public_key);

	int32_t result = LLCRYPTO_SUCCESS;
	MICROEJ_ASYNC_WORKER_job_t *job;
	if (LLCRYPTO_SUCCESS == result) {
		job = MICROEJ_ASYNC_WORKER_get_job_done();
		if (job == NULL) {
			result = LLCRYPTO_ERROR;
			llcrypto_throw(LLCRYPTO_ERROR, "Internal error: cannot retrieve async worker job done");
		}
	}
	if (LLCRYPTO_SUCCESS == result) {
		LLCRYPTO_KEY_AGREEMENT_generate_secret_params_t *params =
			(LLCRYPTO_KEY_AGREEMENT_generate_secret_params_t *)job->params;
		result = params->rc;
		if (LLCRYPTO_SUCCESS == result) {
			llcrypto_memcpy(secret_buffer, params->secret_buffer, params->secret_size);
			/* Wipe the shared secret copy before the job buffer is reused (a plain memset could be optimized away). */
			wc_ForceZero(params->secret_buffer, (size_t)params->secret_size);
			result = params->secret_size;
		} else if (LLCRYPTO_JOB_EXCEPTION == result) {
			llcrypto_throw(params->wolfcrypt_rc, llcrypto_wc_error_message(params->wolfcrypt_rc));
			result = LLCRYPTO_ERROR;
		} else {
			// Nothing to do, the error code is returned without exception in this case.
		}
	}
	if (job != NULL) {
		llcrypto_free_job(job);
	}
	LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE("%s (result=%d ; secret_buffer=0x%x)\n", __func__, result, secret_buffer);
	return result;
}

// --------------------------------------------------------------------------------
// LLCRYPTO_KEY_AGREEMENT_impl.h functions
// --------------------------------------------------------------------------------

// see LLCRYPTO_KEY_AGREEMENT_impl.h
int32_t LLCRYPTO_KEY_AGREEMENT_IMPL_get_algorithm_id(uint8_t *algorithm_name) {
	LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE("%s(algorithm=\"%s\")\n", __func__, algorithm_name);
	return (strcmp("ECDH", (const char *)algorithm_name) == 0) ? 0 : LLCRYPTO_ERROR;
}

// see LLCRYPTO_KEY_AGREEMENT_impl.h
int32_t LLCRYPTO_KEY_AGREEMENT_IMPL_get_max_size(int32_t algorithm, int32_t local_private_key,
                                                 int32_t remote_public_key) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE("%s(priv_key=0x%p, public_key=0x%p)\n", __func__, (void *)local_private_key,
	                                   (void *)remote_public_key);
	/* The key handles only feed the debug trace: the maximum secret size does not depend on them. */
	LLCRYPTO_UNUSED_PARAM(local_private_key);
	LLCRYPTO_UNUSED_PARAM(remote_public_key);
	int32_t result = 0;
	if (algorithm != 0) {
		llcrypto_throw(algorithm, "Internal error: invalid algorithm");
	} else {
		result = 1024; // maybe could be optimized using private_key->dp?
	}
	return result;
}

// see LLCRYPTO_KEY_AGREEMENT_impl.h
int32_t LLCRYPTO_KEY_AGREEMENT_IMPL_generate_secret(int32_t algorithm, int32_t local_private_key,
                                                    int32_t remote_public_key, uint8_t *secret_buffer) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_KEY_AGREEMENT_DEBUG_TRACE("%s(priv_key=0x%p, public_key=0x%p)\n", __func__, (void *)local_private_key,
	                                   (void *)remote_public_key);
	LLCRYPTO_UNUSED_PARAM(secret_buffer);
	int32_t result = LLCRYPTO_SUCCESS;

	if (algorithm != 0) {
		llcrypto_throw(algorithm, "Internal error: invalid algorithm");
		result = LLCRYPTO_ERROR;
	}
	LLCRYPTO_priv_key *priv_key = (LLCRYPTO_priv_key *)local_private_key;
	LLCRYPTO_pub_key *pub_key = (LLCRYPTO_pub_key *)remote_public_key;
	if ((priv_key->algo_type != ALGO_ECDSA) || (pub_key->algo_type != ALGO_ECDSA)) {
		result = LLCRYPTO_ERROR;
	}

	MICROEJ_ASYNC_WORKER_job_t *job = NULL;
	if (result == LLCRYPTO_SUCCESS) {
		job = MICROEJ_ASYNC_WORKER_allocate_job(&llcrypto_worker,
		                                        (SNI_callback)LLCRYPTO_KEY_AGREEMENT_IMPL_generate_secret);
		if (job == NULL) {
			result = LLCRYPTO_ERROR;
			// MICROEJ_ASYNC_WORKER_allocate_job() has thrown a NativeException
		}
	}

	LLCRYPTO_KEY_AGREEMENT_generate_secret_params_t *params = NULL;
	if (result == LLCRYPTO_SUCCESS) {
		params = (LLCRYPTO_KEY_AGREEMENT_generate_secret_params_t *)job->params;
		params->priv_key = priv_key;
		params->pub_key = pub_key;
		int32_t rc = llcrypto_async_exec(job,
		                                 LLCRYPTO_KEY_AGREEMENT_IMPL_generate_secret_job,
		                                 (SNI_callback)LLCRYPTO_KEY_AGREEMENT_IMPL_generate_secret_job_done);
		if (rc != LLCRYPTO_SUCCESS) {
			result = LLCRYPTO_ERROR;
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
		}
	}

	if (result != LLCRYPTO_SUCCESS) {
		if (job != NULL) {
			llcrypto_free_job(job);
		}
	}

	return result;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
