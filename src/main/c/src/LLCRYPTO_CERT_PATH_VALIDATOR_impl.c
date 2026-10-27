/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - Cert Path Validator.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

// This implementation is inspired from the PKIX CertPathValidator implementation from wolfcrypt-jni
// JCE provider:
// https://github.com/wolfSSL/wolfcrypt-jni/blob/master/src/main/java/com/wolfssl/provider/jce/WolfCryptPKIXCertPathValidator.java

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_CERT_PATH_VALIDATOR_impl.h>
#include <LLCRYPTO_ERRORS.h>
#include <LLCRYPTO_common.h>
#include <LLCRYPTO_impl.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

struct LLCRYPTO_CPV {
	WOLFSSL_CERT_MANAGER *cm;
	int verification_failed;
};

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static void LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *params =
		(LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
	LLCRYPTO_CPV *cert_path_validator = params->cpv;
	uint8_t *x509 = params->x509;
	int32_t len = params->x509_length;
	WOLFSSL_CERT_MANAGER *cm = cert_path_validator->cm;
	int32_t format = get_x509_certificate_format((int8_t *)x509, len, NULL, NULL);

	if (J_MEMORY_ERROR == format) {
		// Report the allocation failure as an OOM so that the Java side retries after a GC.
		params->rc = LLCRYPTO_ERROR_OOM;
	} else if ((format != CERT_PEM_FORMAT) && (format != CERT_DER_FORMAT)) {
		LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("get_x509_certificate_format() failed with error: %d\n", format);
		params->rc = LLCRYPTO_ERROR;
	} else {
		int wolfssl_format = (format == CERT_PEM_FORMAT) ? WOLFSSL_FILETYPE_PEM : WOLFSSL_FILETYPE_ASN1;
		int wolfssl_ret = wolfSSL_CertManagerLoadCABuffer(cm, (unsigned char const *)x509, len, wolfssl_format);
		if ((WOLFSSL_SUCCESS != wolfssl_ret) && (MEMORY_E != wolfssl_ret)) {
			LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("wolfSSL_CertManagerLoadCABuffer() failed with error: %d\n",
			                                         wolfssl_ret);
		}
		if (wolfssl_ret == WOLFSSL_SUCCESS) {
			params->rc = LLCRYPTO_SUCCESS;
		} else if (wolfssl_ret == MEMORY_E) {
			params->rc = LLCRYPTO_ERROR_OOM;
		} else {
			params->rc = LLCRYPTO_ERROR;
		}
	}
	llcrypto_free(params->x509);
}

static int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate_job_done(int32_t cpv, uint8_t *x509) {
	LLCRYPTO_UNUSED_PARAM(cpv);
	LLCRYPTO_UNUSED_PARAM(x509);
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
		const LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *params =
			(LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
		result = params->rc;
	}
	if (job != NULL) {
		llcrypto_free_job(job);
	}
	return result;
}

static void LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *params =
		(LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
	LLCRYPTO_CPV *cert_path_validator = params->cpv;
	uint8_t *x509 = params->x509;
	int32_t len = params->x509_length;
	WOLFSSL_CERT_MANAGER *cm = cert_path_validator->cm;
	int32_t format = get_x509_certificate_format((int8_t *)x509, len, NULL, NULL);

	if (J_MEMORY_ERROR == format) {
		// Report the allocation failure as an OOM so that the Java side retries after a GC.
		params->rc = LLCRYPTO_ERROR_OOM;
	} else if ((format != CERT_PEM_FORMAT) && (format != CERT_DER_FORMAT)) {
		LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("get_x509_certificate_format() failed with error: %d\n", format);
		params->rc = LLCRYPTO_ERROR;
	} else {
		int wolfssl_format = (format == CERT_PEM_FORMAT) ? WOLFSSL_FILETYPE_PEM : WOLFSSL_FILETYPE_ASN1;
		int wolfssl_ret = wolfSSL_CertManagerVerifyBuffer(cm, (unsigned char const *)x509, len, wolfssl_format);
		if (WOLFSSL_SUCCESS == wolfssl_ret) {
			// After verifying the certificate, add it to the list of CAs before verifying next
			// certificates in the chain
			wolfssl_ret = wolfSSL_CertManagerLoadCABuffer(cm, (unsigned char const *)x509, len, wolfssl_format);
			if ((WOLFSSL_SUCCESS != wolfssl_ret) && (MEMORY_E != wolfssl_ret)) {
				LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("wolfSSL_CertManagerLoadCABuffer() failed with error: %d\n",
				                                         wolfssl_ret);
			}
		} else if ((ASN_SIG_CONFIRM_E == wolfssl_ret) || (ASN_NO_SIGNER_E == wolfssl_ret)) {
			cert_path_validator->verification_failed = 1;
			wolfssl_ret = WOLFSSL_SUCCESS; // certificate was correctly loaded but verification failed
		} else if (MEMORY_E == wolfssl_ret) {
			// no need to log, the error is correctly reified
		} else {
			LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("wolfSSL_CertManagerVerifyBuffer() failed with error: %d\n",
			                                         wolfssl_ret);
		}

		if (wolfssl_ret == WOLFSSL_SUCCESS) {
			params->rc = LLCRYPTO_SUCCESS;
		} else if (wolfssl_ret == MEMORY_E) {
			params->rc = LLCRYPTO_ERROR_OOM;
		} else {
			params->rc = LLCRYPTO_ERROR;
		}
	}
	llcrypto_free(params->x509);
}

static int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path_job_done(int32_t cpv, uint8_t *x509) {
	LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s()\n", __func__);
	LLCRYPTO_UNUSED_PARAM(cpv);
	LLCRYPTO_UNUSED_PARAM(x509);
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
		const LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *params =
			(LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
		result = params->rc;
	}
	if (job != NULL) {
		llcrypto_free_job(job);
	}
	return result;
}

// --------------------------------------------------------------------------------
// LLCRYPTO_CERT_PATH_VALIDATOR_impl.h functions
// --------------------------------------------------------------------------------

// see LLCRYPTO_CERT_PATH_VALIDATOR_impl.h
int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_new_cert_path_validator(void) {
	LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s()\n", __func__);
	LLCRYPTO_CPV *cpv = llcrypto_calloc(1, sizeof(LLCRYPTO_CPV));
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();
	int32_t result = LLCRYPTO_SUCCESS;

	if (cpv == NULL) {
		result = LLCRYPTO_ERROR_OOM;
	} else {
		if (SNI_OK != SNI_registerResource((void *)cpv,
		                                   (SNI_closeFunction)
		                                   LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_close_cert_path_validator,
		                                   NULL)) {
			llcrypto_free(cpv);
			llcrypto_throw(LLCRYPTO_ERROR, "Could not register SNI native resource");
			result = LLCRYPTO_ERROR;
		}

		if (LLCRYPTO_SUCCESS == result) {
			WOLFSSL_CERT_MANAGER *cm = wolfSSL_CertManagerNew_ex(pHint);
			if (cm == NULL) {
				llcrypto_free(cpv);
				result = LLCRYPTO_ERROR_OOM;
			} else {
				cpv->cm = cm;
				result = (int32_t)cpv;
			}
		}
	}
	return result;
}

// see LLCRYPTO_CERT_PATH_VALIDATOR_impl.h
int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate(int32_t cpv, uint8_t *x509) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s(cpv=0x%p, x509[%d]=0x%p)\n", __func__, (void *)cpv,
	                                         SNI_getArrayLength(x509), x509);
	int32_t result = LLCRYPTO_SUCCESS;

	MICROEJ_ASYNC_WORKER_job_t *job;
	if (result == LLCRYPTO_SUCCESS) {
		job = MICROEJ_ASYNC_WORKER_allocate_job(&llcrypto_worker,
		                                        (SNI_callback)
		                                        LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate);
		if (job == NULL) {
			// MICROEJ_ASYNC_WORKER_allocate_job() has suspended the Java thread or thrown a NativeException
			result = LLCRYPTO_JOB_UNAVAILABLE;
		}
	}

	LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *params = NULL;
	if (result == LLCRYPTO_SUCCESS) {
		params = (LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
		params->cpv = (LLCRYPTO_CPV *)cpv;
		params->x509 = llcrypto_calloc(1, SNI_getArrayLength(x509));
		params->x509_length = SNI_getArrayLength(x509);
		if (params->x509 == NULL) {
			result = LLCRYPTO_ERROR_OOM;
		}
	}

	if (result == LLCRYPTO_SUCCESS) {
		llcrypto_memcpy(params->x509, x509, SNI_getArrayLength(x509));
		int32_t rc = llcrypto_async_exec(job,
		                                 LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate_job,
		                                 (SNI_callback)
		                                 LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate_job_done);
		if (rc != LLCRYPTO_SUCCESS) {
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
			result = LLCRYPTO_JOB_EXCEPTION;
		}
	}

	if (result != LLCRYPTO_SUCCESS) {
		if (job != NULL) {
			llcrypto_free_job(job);
		}
		if ((params != NULL) && (params->x509 != NULL)) {
			llcrypto_free(params->x509);
		}
	}

	// The Java thread is suspended (the job done callback returns the result) or a NativeException is pending: the
	// returned value is ignored. LLCRYPTO_ERROR_OOM is the exception, returned so the Crypto library can run a
	// garbage collection and retry.
	int32_t return_code = SNI_IGNORED_RETURNED_VALUE;
	if (LLCRYPTO_ERROR_OOM == result) {
		return_code = LLCRYPTO_ERROR_OOM;
	}
	return return_code;
}

// see LLCRYPTO_CERT_PATH_VALIDATOR_impl.h
jboolean LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_expect_forward_cert_path(void) {
	LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s()\n", __func__);
	return JFALSE;
}

// see LLCRYPTO_CERT_PATH_VALIDATOR_impl.h
int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path(int32_t cpv, uint8_t *x509) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s(cpv=0x%p, x509[%d]=0x%p)\n", __func__, (void *)cpv,
	                                         SNI_getArrayLength(x509), x509);
	LLCRYPTO_CPV *cert_path_validator = (LLCRYPTO_CPV *)cpv;
	int32_t result = LLCRYPTO_SUCCESS;
	uint8_t skip_append_cert = false;

	if (cert_path_validator->verification_failed != 0) {
		// A previous error is noticed, so we skip the current append and return success, because the error will be
		// triggered when the LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_validate_cert_path function is called.
		LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s() => SKIPPED\n", __func__);
		result = LLCRYPTO_SUCCESS;
		skip_append_cert = true;
	}

	MICROEJ_ASYNC_WORKER_job_t *job;
	if ((result == LLCRYPTO_SUCCESS) && (!skip_append_cert)) {
		job = MICROEJ_ASYNC_WORKER_allocate_job(&llcrypto_worker,
		                                        (SNI_callback)LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path);
		if (job == NULL) {
			// MICROEJ_ASYNC_WORKER_allocate_job() has suspended the Java thread or thrown a NativeException
			result = LLCRYPTO_JOB_UNAVAILABLE;
		}
	}

	LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *params = NULL;
	if ((result == LLCRYPTO_SUCCESS) && (!skip_append_cert)) {
		params = (LLCRYPTO_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
		params->cpv = cert_path_validator;
		params->x509 = llcrypto_calloc(1, SNI_getArrayLength(x509));
		params->x509_length = SNI_getArrayLength(x509);
		if (params->x509 == NULL) {
			result = LLCRYPTO_ERROR_OOM;
		}
	}

	if ((result == LLCRYPTO_SUCCESS) && (!skip_append_cert)) {
		llcrypto_memcpy(params->x509, x509, SNI_getArrayLength(x509));
		int32_t rc = llcrypto_async_exec(job,
		                                 LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path_job,
		                                 (SNI_callback)LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path_job_done);
		if (rc != LLCRYPTO_SUCCESS) {
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
			result = LLCRYPTO_JOB_EXCEPTION;
		}
	}

	if (result != LLCRYPTO_SUCCESS) {
		if (job != NULL) {
			llcrypto_free_job(job);
		}
		if ((params != NULL) && (params->x509 != NULL)) {
			llcrypto_free(params->x509);
		}
	}

	int32_t return_code;
	if (0u != skip_append_cert) {
		return_code = LLCRYPTO_SUCCESS;
	} else if (LLCRYPTO_ERROR_OOM == result) {
		// Returned so the Crypto library can run a garbage collection and retry.
		return_code = LLCRYPTO_ERROR_OOM;
	} else {
		// The Java thread is suspended (the job done callback returns the result) or a NativeException is pending:
		// the returned value is ignored.
		return_code = SNI_IGNORED_RETURNED_VALUE;
	}
	return return_code;
}

// see LLCRYPTO_CERT_PATH_VALIDATOR_impl.h
int32_t LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_validate_cert_path(int32_t cpv) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s(cpv=0x%p)\n", __func__, (void *)cpv);
	const LLCRYPTO_CPV *cert_path_validator = (LLCRYPTO_CPV *)cpv;
	return (cert_path_validator->verification_failed == 0) ? LLCRYPTO_SUCCESS : LLCRYPTO_ERROR;
}

// see LLCRYPTO_CERT_PATH_VALIDATOR_impl.h
void LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_close_cert_path_validator(int32_t cpv) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s(cpv=0x%p)\n", __func__, (void *)cpv);
	LLCRYPTO_CPV *cert_path_validator = (LLCRYPTO_CPV *)cpv;
	WOLFSSL_CERT_MANAGER *cm = cert_path_validator->cm;

	wolfSSL_CertManagerFree(cm);
	llcrypto_free(cert_path_validator);
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	if (SNI_OK != SNI_unregisterResource((void *)cpv,
	                                     (SNI_closeFunction)LLCRYPTO_CERT_PATH_VALIDATOR_IMPL_close_cert_path_validator))
	{
		llcrypto_throw(LLCRYPTO_ERROR, "Can't unregister SNI native resource");
	}
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
