/*
 * Copyright 2024-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - X509 Certificates.
 * @author MicroEJ Developer Team
 * @version 2.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLCRYPTO_X509_CERT_impl.h>
#include <LLCRYPTO_wolfcrypt.h>
#include <LLCRYPTO_common.h>

#include <sni.h>
#include <stdlib.h>
#include <string.h>

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static int32_t LLCRYPTO_X509_CERT_wolfcrypt_close_key(int32_t native_id);

/**
 * @brief   Frees the resources and context associated of an Wolfcrypt public key structure.
 *
 * @param[in]  native_id  Reference to the public key structure
 *
 * @return     LLCRYPTO_SUCCESS if the creation is successful,  LLCRYPTO_ERROR otherwise.
 *
 */
static int32_t LLCRYPTO_X509_CERT_wolfcrypt_close_key(int32_t native_id) {
	LLCRYPTO_X509_DEBUG_TRACE("%s \n", __func__);
	int return_code = LLCRYPTO_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_pub_key *key = (LLCRYPTO_pub_key *)native_id;

	switch (key->algo_type) {
#ifndef NO_RSA
	case ALGO_RSA:
		wc_FreeRsaKey(key->rsa_key);
		break;
#endif // NO_RSA
	case ALGO_ECDSA:
		wc_ecc_free(key->ec_key);
		break;
	default:
		// this should never happen
		break;
	}

	llcrypto_free(key->any_key);
	llcrypto_free(key);
	return return_code;
}

// --------------------------------------------------------------------------------
// LLCRYPTO_X509_CERT_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLCRYPTO_X509_CERT_IMPL_parse(int8_t *cert, int32_t off, int32_t len) {
	LLCRYPTO_X509_DEBUG_TRACE("%s(cert=%p, off=%d, len=%d)\n", __func__, cert, (int)off, (int)len);
	int32_t format = LLCRYPTO_X509_UNKNOWN_FORMAT;
	int8_t *cert_data = &cert[off];
	format = get_x509_certificate_format(cert_data, len, NULL, NULL);
	if (format == CERT_PEM_FORMAT) {
		LLCRYPTO_X509_DEBUG_TRACE("%s() => PEM\n", __func__);
	} else if (format == CERT_DER_FORMAT) {
		LLCRYPTO_X509_DEBUG_TRACE("%s() => DER\n", __func__);
	} else {
		LLCRYPTO_X509_DEBUG_TRACE("%s() => ERROR(%d)\n", __func__, format);
	}
	return format;
}

// See the header file for the function documentation
int32_t LLCRYPTO_X509_CERT_IMPL_get_x500_principal_data(int8_t *cert_data, int32_t cert_data_length,
                                                        uint8_t *principal_data, int32_t principal_data_length,
                                                        uint8_t get_issuer) {
	int32_t return_code = LLCRYPTO_SUCCESS;
	LLCRYPTO_X509_DEBUG_TRACE("%s(cert=%p, Cert_len=%d,prin_len=%d,get_issuer=%d)\n", __func__, cert_data,
	                          (int)cert_data_length, (int)principal_data_length, (int)get_issuer);
	DecodedCert *certificate;

	(void)get_x509_certificate_format(cert_data, cert_data_length, &certificate, NULL);
	if (NULL == certificate) {
		llcrypto_throw(LLCRYPTO_ERROR, "Bad x509 certificate");
		return_code = LLCRYPTO_ERROR;
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		int len;

		if ((uint8_t)0 != get_issuer) {
			len = strlen(certificate->issuer);
		} else {
			len = strlen(certificate->subject);
		}

		if (len > principal_data_length) {
			llcrypto_throw(LLCRYPTO_ERROR, "Principal data buffer is too small");
			return_code = LLCRYPTO_ERROR;
		} else {
			if ((uint8_t)0 != get_issuer) {
				len = strlen(certificate->issuer);
				llcrypto_strncpy(principal_data, certificate->issuer, principal_data_length);
			} else {
				len = strlen(certificate->subject);
				llcrypto_strncpy(principal_data, certificate->subject, principal_data_length);
			}
			wc_FreeDecodedCert(certificate);
			llcrypto_free(certificate);

			return_code = len;
		}
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_X509_CERT_IMPL_get_key(int8_t *cert_data, int32_t cert_data_length) {
	int32_t return_code = LLCRYPTO_SUCCESS;
	DecodedCert *certificate = NULL;
	void *native_id = NULL;
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

	LLCRYPTO_X509_DEBUG_TRACE("%s(cert=%p, len=%d)\n", __func__, cert_data, (int)cert_data_length);

	LLCRYPTO_pub_key *pub_key = (LLCRYPTO_pub_key *)llcrypto_calloc(1, sizeof(LLCRYPTO_pub_key));
	if (NULL == pub_key) {
		llcrypto_throw(LLCRYPTO_ERROR_OOM, "Can't allocate LLCRYPTO_pub_key structure");
		return_code = LLCRYPTO_ERROR_OOM;
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		(void)get_x509_certificate_format(cert_data, cert_data_length, &certificate, NULL);
		if (NULL == certificate) {
			llcrypto_throw(LLCRYPTO_ERROR, "Bad x509 certificate");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		// get public key len
		word32 pk_der_size = 0;
		byte *pk_der_buffer;
		// get needed buffer size
		wc_GetPubKeyDerFromCert(certificate, NULL, &pk_der_size);

		// allocate the public key buffer
		pk_der_buffer = (byte *)llcrypto_calloc(1, pk_der_size);
		if (NULL == pk_der_buffer) {
			llcrypto_throw(LLCRYPTO_ERROR_OOM, "Can't allocate a public key DER buffer");
			return_code = LLCRYPTO_ERROR_OOM;
		}
		if (LLCRYPTO_SUCCESS == return_code) {
			int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
			// extract DER public key
			wolfcrypt_rc = wc_GetPubKeyDerFromCert(certificate, pk_der_buffer, &pk_der_size);
			if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
				llcrypto_throw(LLCRYPTO_ERROR, "Failed to extract DER public key!");
				return_code = LLCRYPTO_ERROR;
			}

			if (LLCRYPTO_SUCCESS == return_code) {
				// create the wolfcrypt key structure:
				word32 idx = 0;
				// tracks whether an allocation below failed, so the single throw below
				// reports OOM instead of a generic "unsupported algorithm" error
				bool oom_occurred = false;
#ifndef NO_RSA
				// try to parse an RSA key
				RsaKey *tmp_rsakey;
				tmp_rsakey = llcrypto_calloc(1, sizeof(RsaKey));
				if (NULL == tmp_rsakey) {
					oom_occurred = true;
				} else {
					int wolfcrypt_rc_rsa_init = wc_InitRsaKey(tmp_rsakey, pHint);
					wolfcrypt_rc = wc_RsaPublicKeyDecode(pk_der_buffer, &idx, tmp_rsakey, pk_der_size);
					if ((LLCRYPTO_WOLFCRYPT_SUCCESS == wolfcrypt_rc) &&
					    (LLCRYPTO_WOLFCRYPT_SUCCESS == wolfcrypt_rc_rsa_init)) {
						pub_key->algo_type = ALGO_RSA;
						pub_key->rsa_key = tmp_rsakey;
						pub_key->key_type = LLCRYPTO_KEY_TYPE_PUBLIC;
					} else {
						wc_FreeRsaKey(tmp_rsakey);
						llcrypto_free(tmp_rsakey);
					}
				}
#endif // NO_RSA
				if (NULL == pub_key->any_key) {
					// try to parse an EC key
					ecc_key *tmp_ecc_key;
					tmp_ecc_key = llcrypto_calloc(1, sizeof(ecc_key));
					if (NULL == tmp_ecc_key) {
						oom_occurred = true;
					} else {
						int wolfcrypt_rc_ecc_init = wc_ecc_init_ex(tmp_ecc_key, pHint, INVALID_DEVID);
						wolfcrypt_rc = wc_EccPublicKeyDecode(pk_der_buffer, &idx, tmp_ecc_key, pk_der_size);
						if ((LLCRYPTO_WOLFCRYPT_SUCCESS == wolfcrypt_rc) &&
						    (LLCRYPTO_WOLFCRYPT_SUCCESS == wolfcrypt_rc_ecc_init)) {
							pub_key->algo_type = ALGO_ECDSA;
							pub_key->ec_key = tmp_ecc_key;
							pub_key->key_type = LLCRYPTO_KEY_TYPE_PUBLIC;
						} else {
							wc_ecc_free(tmp_ecc_key);
							llcrypto_free(tmp_ecc_key);
						}
					}
				}

				if (NULL == pub_key->any_key) {
					if (oom_occurred) {
						llcrypto_throw(LLCRYPTO_ERROR_OOM, "Can't allocate RSA/ECC key structure");
						return_code = LLCRYPTO_ERROR_OOM;
					} else {
						llcrypto_throw(LLCRYPTO_ERROR, "Cannot extract public key: unsupported algorithm");
						return_code = LLCRYPTO_ERROR;
					}
				}
			}
		}

		if (NULL != pk_der_buffer) {
			llcrypto_free(pk_der_buffer);
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		native_id = (void *)pub_key;
		if (SNI_OK != SNI_registerResource(native_id, (SNI_closeFunction)LLCRYPTO_X509_CERT_wolfcrypt_close_key,
		                                   NULL)) {
			llcrypto_throw(LLCRYPTO_ERROR, "Can't register SNI native resource");
			switch (pub_key->algo_type) {
#ifndef NO_RSA
			case ALGO_RSA:
				wc_FreeRsaKey(pub_key->rsa_key);
				break;
#endif // NO_RSA
			case ALGO_ECDSA:
				wc_ecc_free(pub_key->ec_key);
				break;
			default:
				// this should never happen
				break;
			}

			llcrypto_free(pub_key->any_key);
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (LLCRYPTO_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		return_code = (uint32_t)native_id;
	} else {
		if (NULL != pub_key) {
			llcrypto_free(pub_key);
		}
	}

	if (NULL != certificate) {
		wc_FreeDecodedCert(certificate);
		llcrypto_free(certificate);
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_X509_CERT_IMPL_verify(int8_t *cert_data, int32_t cert_data_length, int32_t public_key_id) {
	// cppcheck-suppress [misra-c2012-11.6]: void pointer cast to display the address targeted.
	LLCRYPTO_X509_DEBUG_TRACE("%s(cert=%p, len=%d, pubkey=%p)\n", __func__, cert_data, cert_data_length,
	                          (void *)public_key_id);
	LLCRYPTO_UNUSED_PARAM(public_key_id);
	WOLFSSL_HEAP_HINT *pHint = llcrypto_wolfssl_get_heap();

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_SMALL_CERT_VERIFY)
	int return_code = LLCRYPTO_SUCCESS;
	int wolfcrypt_rc = LLCRYPTO_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLCRYPTO_pub_key *key = (LLCRYPTO_pub_key *)public_key_id;
	byte *key_buffer = NULL;
	word32 key_buffer_size;
	int pubKeyOID;

	// First, encode key into DER format (required by WolfCrypt certificate signature verification API)
	switch (key->algo_type) {
#ifndef NO_RSA
	case ALGO_RSA:
		pubKeyOID = RSAk;
		wolfcrypt_rc = wc_RsaPublicKeyDerSize(key->rsa_key, 1);
		break;
#endif // NO_RSA
	case ALGO_ECDSA:
		pubKeyOID = ECDSAk;
		wolfcrypt_rc = wc_EccPublicKeyDerSize((ecc_key *)key->any_key, 1);
		break;
	default:
		// this should never happen
		break;
	}
	if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
		llcrypto_throw(wolfcrypt_rc, "Could not encode public key: failed to calculate size");
		return_code = LLCRYPTO_ERROR;
	} else {
		key_buffer_size = wolfcrypt_rc;
	}

	if (return_code == LLCRYPTO_SUCCESS) {
		key_buffer = llcrypto_calloc(key_buffer_size, sizeof(byte));
		if (NULL == key_buffer) {
			llcrypto_throw(LLCRYPTO_ERROR, "Could not encode public key: not enough memory");
			return_code = LLCRYPTO_ERROR;
		} else {
			switch (key->algo_type) {
#ifndef NO_RSA
			case ALGO_RSA:
				wolfcrypt_rc = wc_RsaKeyToPublicDer((RsaKey *)key->rsa_key, key_buffer, key_buffer_size);
				break;
#endif // NO_RSA
			case ALGO_ECDSA:
				wolfcrypt_rc = wc_EccPublicKeyToDer((ecc_key *)key->ec_key, key_buffer, key_buffer_size, 1);
				break;
			default:
				// this should never happen
				break;
			}
			if (LLCRYPTO_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
				llcrypto_throw(wolfcrypt_rc, "Could not encode public key");
				return_code = LLCRYPTO_ERROR;
			}
		}
	}

	if (return_code == LLCRYPTO_SUCCESS) {
		wolfcrypt_rc = wc_CheckCertSigPubKey((byte *)cert_data, cert_data_length, pHint, key_buffer, key_buffer_size,
		                                     pubKeyOID);
		if (LLCRYPTO_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			llcrypto_throw(wolfcrypt_rc, "Certificate signature verification failed");
			return_code = LLCRYPTO_ERROR;
		}
	}

	if (NULL != key_buffer) {
		llcrypto_free(key_buffer);
	}

	return return_code;
#else
	llcrypto_throw(LLCRYPTO_ERROR, "Certificate signature verification not available");
	return SNI_IGNORED_RETURNED_VALUE;
#endif /* OPENSSL_EXTRA || WOLFSSL_SMALL_CERT_VERIFY */
}

// See the header file for the function documentation
int32_t LLCRYPTO_X509_CERT_IMPL_check_validity(int8_t *cert_data, int32_t cert_data_length) {
	LLCRYPTO_X509_DEBUG_TRACE("%s \n", __func__);
	int return_code = LLCRYPTO_SUCCESS;
	DecodedCert *certificate;
	int32_t check_error;

	(void)get_x509_certificate_format(cert_data, cert_data_length, &certificate, &check_error);
	if (NULL == certificate) {
		switch (check_error) {
		case ASN_AFTER_DATE_E:
			return_code = J_X509_CERT_EXPIRED_ERROR;
			break;
		case ASN_BEFORE_DATE_E:
			return_code = J_X509_CERT_NOT_YET_VALID_ERROR;
			break;
		case ASN_DATE_SZ_E:
			return_code = J_DATE_ERROR;
			break;
		default:
			llcrypto_throw(LLCRYPTO_ERROR, "Bad x509 certificate");
			return_code = LLCRYPTO_ERROR;
			break;
		}
	} else {
		return_code = J_SEC_NO_ERROR;
	}

	if (NULL != certificate) {
		wc_FreeDecodedCert(certificate);
		llcrypto_free(certificate);
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLCRYPTO_X509_CERT_IMPL_get_close_key(void) {
	LLCRYPTO_X509_DEBUG_TRACE("%s \n", __func__);
	return (int32_t)LLCRYPTO_X509_CERT_wolfcrypt_close_key;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
