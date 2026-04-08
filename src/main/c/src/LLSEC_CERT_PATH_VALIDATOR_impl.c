/*
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Cert Path Validator.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// This implementation is inspired from the PKIX CertPathValidator implementation from wolfcrypt-jni
// JCE provider:
// https://github.com/wolfSSL/wolfcrypt-jni/blob/master/src/main/java/com/wolfssl/provider/jce/WolfCryptPKIXCertPathValidator.java

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_CERT_PATH_VALIDATOR_impl.h>
#include <LLSEC_ERRORS.h>
#include <LLSEC_common.h>
#include <LLSEC_impl.h>

#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

struct LLSEC_CPV {
	WOLFSSL_CERT_MANAGER *cm;
	int verification_failed;
};

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static void LLSEC_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *params =
		(LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
	LLSEC_CPV *cert_path_validator = params->cpv;
	uint8_t *x509 = params->x509;
	int32_t len = params->x509_length;
	WOLFSSL_CERT_MANAGER *cm = cert_path_validator->cm;
	int32_t format = get_x509_certificate_format((int8_t *)x509, len, NULL, NULL);

	if ((format != CERT_PEM_FORMAT) && (format != CERT_DER_FORMAT)) {
		LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("get_x509_certificate_format() failed with error: %d\n", format);
		params->rc = LLSEC_ERROR;
	} else {
		int wolfssl_format = (format == CERT_PEM_FORMAT) ? WOLFSSL_FILETYPE_PEM : WOLFSSL_FILETYPE_ASN1;
		int wolfssl_ret = wolfSSL_CertManagerLoadCABuffer(cm, (unsigned char const *)x509, len, wolfssl_format);
		if ((WOLFSSL_SUCCESS != wolfssl_ret) && (MEMORY_E != wolfssl_ret)) {
			LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("wolfSSL_CertManagerLoadCABuffer() failed with error: %d\n",
			                                      wolfssl_ret);
		}
		if (wolfssl_ret == WOLFSSL_SUCCESS) {
			params->rc = LLSEC_SUCCESS;
		} else if (wolfssl_ret == MEMORY_E) {
			params->rc = LLSEC_ERROR_OOM;
		} else {
			params->rc = LLSEC_ERROR;
		}
	}
	llsec_free(params->x509);
}

static int32_t LLSEC_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate_job_done(int32_t cpv, uint8_t *x509) {
	LLSEC_UNUSED_PARAM(cpv);
	LLSEC_UNUSED_PARAM(x509);
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
		const LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *params =
			(LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
		result = params->rc;
	}
	if (job != NULL) {
		llsec_free_job(job);
	}
	return result;
}

static void LLSEC_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path_job(MICROEJ_ASYNC_WORKER_job_t *job) {
	LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *params =
		(LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
	LLSEC_CPV *cert_path_validator = params->cpv;
	uint8_t *x509 = params->x509;
	int32_t len = params->x509_length;
	WOLFSSL_CERT_MANAGER *cm = cert_path_validator->cm;
	int32_t format = get_x509_certificate_format((int8_t *)x509, len, NULL, NULL);

	if ((format != CERT_PEM_FORMAT) && (format != CERT_DER_FORMAT)) {
		LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("get_x509_certificate_format() failed with error: %d\n", format);
		params->rc = LLSEC_ERROR;
	} else {
		int wolfssl_format = (format == CERT_PEM_FORMAT) ? WOLFSSL_FILETYPE_PEM : WOLFSSL_FILETYPE_ASN1;
		int wolfssl_ret = wolfSSL_CertManagerVerifyBuffer(cm, (unsigned char const *)x509, len, wolfssl_format);
		if (WOLFSSL_SUCCESS == wolfssl_ret) {
			// After verifying the certificate, add it to the list of CAs before verifying next
			// certificates in the chain
			wolfssl_ret = wolfSSL_CertManagerLoadCABuffer(cm, (unsigned char const *)x509, len, wolfssl_format);
			if ((WOLFSSL_SUCCESS != wolfssl_ret) && (MEMORY_E != wolfssl_ret)) {
				LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("wolfSSL_CertManagerLoadCABuffer() failed with error: %d\n",
				                                      wolfssl_ret);
			}
		} else if ((ASN_SIG_CONFIRM_E == wolfssl_ret) || (ASN_NO_SIGNER_E == wolfssl_ret)) {
			cert_path_validator->verification_failed = 1;
			wolfssl_ret = WOLFSSL_SUCCESS; // certificate was correctly loaded but verification failed
		} else if (MEMORY_E == wolfssl_ret) {
			// no need to log, the error is correctly reified
		} else {
			LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("wolfSSL_CertManagerVerifyBuffer() failed with error: %d\n",
			                                      wolfssl_ret);
		}

		if (wolfssl_ret == WOLFSSL_SUCCESS) {
			params->rc = LLSEC_SUCCESS;
		} else if (wolfssl_ret == MEMORY_E) {
			params->rc = LLSEC_ERROR_OOM;
		} else {
			params->rc = LLSEC_ERROR;
		}
	}
	llsec_free(params->x509);
}

static int32_t LLSEC_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path_job_done(int32_t cpv, uint8_t *x509) {
	LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s()\n", __func__);
	LLSEC_UNUSED_PARAM(cpv);
	LLSEC_UNUSED_PARAM(x509);
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
		const LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *params =
			(LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
		result = params->rc;
	}
	if (job != NULL) {
		llsec_free_job(job);
	}
	return result;
}

// --------------------------------------------------------------------------------
// LLSEC_CERT_PATH_VALIDATOR_impl.h functions
// --------------------------------------------------------------------------------

// see LLSEC_CERT_PATH_VALIDATOR_impl.h
int32_t LLSEC_CERT_PATH_VALIDATOR_IMPL_new_cert_path_validator(void) {
	LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s()\n", __func__);
	LLSEC_CPV *cpv = llsec_calloc(1, sizeof(LLSEC_CPV));
	WOLFSSL_HEAP_HINT *pHint = llsec_wolfssl_get_heap();
	int32_t result = LLSEC_SUCCESS;

	if (cpv == NULL) {
		result = LLSEC_ERROR_OOM;
	} else {
		if (SNI_OK != SNI_registerResource((void *)cpv,
		                                   (SNI_closeFunction)LLSEC_CERT_PATH_VALIDATOR_IMPL_close_cert_path_validator,
		                                   NULL)) {
			llsec_free(cpv);
			llsec_throw(LLSEC_ERROR, "Could not register SNI native resource");
			result = LLSEC_ERROR;
		}

		if (LLSEC_SUCCESS == result) {
			WOLFSSL_CERT_MANAGER *cm = wolfSSL_CertManagerNew_ex(pHint);
			if (cm == NULL) {
				llsec_free(cpv);
				result = LLSEC_ERROR_OOM;
			} else {
				cpv->cm = cm;
				result = (int32_t)cpv;
			}
		}
	}
	return result;
}

// see LLSEC_CERT_PATH_VALIDATOR_impl.h
int32_t LLSEC_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate(int32_t cpv, uint8_t *x509) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s(cpv=0x%p, x509[%d]=0x%p)\n", __func__, (void *)cpv,
	                                      SNI_getArrayLength(x509), x509);
	int32_t result = LLSEC_SUCCESS;

	MICROEJ_ASYNC_WORKER_job_t *job;
	if (result == LLSEC_SUCCESS) {
		job = MICROEJ_ASYNC_WORKER_allocate_job(&llsec_worker,
		                                        (SNI_callback)LLSEC_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate);
		if (job == NULL) {
			// MICROEJ_ASYNC_WORKER_allocate_job() has thrown a NativeException
			result = LLSEC_ERROR_EXCEPTION;
		}
	}

	LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *params = NULL;
	if (result == LLSEC_SUCCESS) {
		params = (LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
		params->cpv = (LLSEC_CPV *)cpv;
		params->x509 = llsec_calloc(1, SNI_getArrayLength(x509));
		params->x509_length = SNI_getArrayLength(x509);
		if (params->x509 == NULL) {
			result = LLSEC_ERROR_OOM;
		}
	}

	if (result == LLSEC_SUCCESS) {
		llsec_memcpy(params->x509, x509, SNI_getArrayLength(x509));
		int32_t rc = llsec_async_exec(job,
		                              LLSEC_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate_job,
		                              (SNI_callback)LLSEC_CERT_PATH_VALIDATOR_IMPL_append_trusted_certificate_job_done);
		if (rc != LLSEC_SUCCESS) {
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
			result = LLSEC_ERROR_EXCEPTION;
		}
	}

	if (result != LLSEC_SUCCESS) {
		if (job != NULL) {
			llsec_free_job(job);
		}
		if ((params != NULL) && (params->x509 != NULL)) {
			llsec_free(params->x509);
		}
	}

	return result;
}

// see LLSEC_CERT_PATH_VALIDATOR_impl.h
jboolean LLSEC_CERT_PATH_VALIDATOR_IMPL_expect_forward_cert_path(void) {
	LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s()\n", __func__);
	return JFALSE;
}

// see LLSEC_CERT_PATH_VALIDATOR_impl.h
int32_t LLSEC_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path(int32_t cpv, uint8_t *x509) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s(cpv=0x%p, x509[%d]=0x%p)\n", __func__, (void *)cpv,
	                                      SNI_getArrayLength(x509), x509);
	LLSEC_CPV *cert_path_validator = (LLSEC_CPV *)cpv;
	int32_t result = LLSEC_SUCCESS;
	uint8_t skip_append_cert = false;

	if (cert_path_validator->verification_failed != 0) {
		// A previous error is noticed, so we skip the current append and return success, because the error will be
		// triggered when the LLSEC_CERT_PATH_VALIDATOR_IMPL_validate_cert_path function is called.
		LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s() => SKIPPED\n", __func__);
		result = LLSEC_SUCCESS;
		skip_append_cert = true;
	}

	MICROEJ_ASYNC_WORKER_job_t *job;
	if ((result == LLSEC_SUCCESS) && (!skip_append_cert)) {
		job = MICROEJ_ASYNC_WORKER_allocate_job(&llsec_worker,
		                                        (SNI_callback)LLSEC_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path);
		if (job == NULL) {
			// MICROEJ_ASYNC_WORKER_allocate_job() has thrown a NativeException
			result = LLSEC_ERROR_EXCEPTION;
		}
	}

	LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *params = NULL;
	if ((result == LLSEC_SUCCESS) && (!skip_append_cert)) {
		params = (LLSEC_CERT_PATH_VALIDATOR_verify_cert_params_t *)job->params;
		params->cpv = cert_path_validator;
		params->x509 = llsec_calloc(1, SNI_getArrayLength(x509));
		params->x509_length = SNI_getArrayLength(x509);
		if (params->x509 == NULL) {
			result = LLSEC_ERROR_OOM;
		}
	}

	if ((result == LLSEC_SUCCESS) && (!skip_append_cert)) {
		llsec_memcpy(params->x509, x509, SNI_getArrayLength(x509));
		int32_t rc = llsec_async_exec(job,
		                              LLSEC_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path_job,
		                              (SNI_callback)LLSEC_CERT_PATH_VALIDATOR_IMPL_append_cert_to_path_job_done);
		if (rc != LLSEC_SUCCESS) {
			// MICROEJ_ASYNC_WORKER_async_exec() has thrown a NativeException
			result = LLSEC_ERROR_EXCEPTION;
		}
	}

	if (result != LLSEC_SUCCESS) {
		if (job != NULL) {
			llsec_free_job(job);
		}
		if ((params != NULL) && (params->x509 != NULL)) {
			llsec_free(params->x509);
		}
	}

	return result;
}

// see LLSEC_CERT_PATH_VALIDATOR_impl.h
int32_t LLSEC_CERT_PATH_VALIDATOR_IMPL_validate_cert_path(int32_t cpv) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s(cpv=0x%p)\n", __func__, (void *)cpv);
	const LLSEC_CPV *cert_path_validator = (LLSEC_CPV *)cpv;
	return (cert_path_validator->verification_failed == 0) ? LLSEC_SUCCESS : LLSEC_ERROR;
}

// see LLSEC_CERT_PATH_VALIDATOR_impl.h
void LLSEC_CERT_PATH_VALIDATOR_IMPL_close_cert_path_validator(int32_t cpv) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLSEC_CERT_PATH_VALIDATOR_DEBUG_TRACE("%s(cpv=0x%p)\n", __func__, (void *)cpv);
	LLSEC_CPV *cert_path_validator = (LLSEC_CPV *)cpv;
	WOLFSSL_CERT_MANAGER *cm = cert_path_validator->cm;

	wolfSSL_CertManagerFree(cm);
	llsec_free(cert_path_validator);
	// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
	if (SNI_OK != SNI_unregisterResource((void *)cpv,
	                                     (SNI_closeFunction)LLSEC_CERT_PATH_VALIDATOR_IMPL_close_cert_path_validator)) {
		llsec_throw(LLSEC_ERROR, "Can't unregister SNI native resource");
	}
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
