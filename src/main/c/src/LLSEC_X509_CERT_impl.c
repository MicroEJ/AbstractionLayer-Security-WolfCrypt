/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - X509 Certificates.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_X509_CERT_impl.h>
#include <sni.h>
#include <stdlib.h>
#include <string.h>
#include <LLSEC_wolfcrypt.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define LLSEC_X509_UNKNOWN_FORMAT ((int)(-1))

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static int32_t get_x509_certificate_format(int8_t *cert_data, int32_t len, DecodedCert **cert_object,
                                           int32_t *check_error);
static int32_t LLSEC_X509_CERT_wolfcrypt_close_key(int32_t native_id);

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
static int32_t get_x509_certificate_format(int8_t *cert_data, int32_t len, DecodedCert **cert_object,
                                           int32_t *check_error) {
	LLSEC_X509_DEBUG_TRACE("%s 00. cert_len:%d\n", __func__, (int)len);

	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	int return_code = LLSEC_X509_UNKNOWN_FORMAT;

	if (NULL != cert_object) {
		*cert_object = NULL;
	}

	/* Allocate a new X509 certificate */
	DecodedCert *new_cert = NULL;
	new_cert = (DecodedCert *)LLSEC_calloc(1, sizeof(DecodedCert));
	if (NULL == new_cert) {
		return_code = J_MEMORY_ERROR;
	} else {
		/* Initialize the X509 certificate */
		wc_InitDecodedCert(new_cert, (byte const *)cert_data, len, NULL);

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
			LLSEC_X509_DEBUG_TRACE("%s. wc_ParseCert() fail, return_code: %d\n", __func__, wolfcrypt_rc);
		}
		if (NULL == cert_object) {
			wc_FreeDecodedCert(new_cert);
			LLSEC_free(new_cert);
		}
	}

	if (CERT_DER_FORMAT != return_code) {
		/* Allocate buffer for DER */
		byte *der_buffer = LLSEC_calloc(len, sizeof(byte));
		if (NULL == new_cert) {
			return_code = J_MEMORY_ERROR;
		} else {
			/* Parse the X509 PEM certificate */
			int32_t der_len = wc_CertPemToDer((byte const *)cert_data, len, der_buffer, len, CERT_TYPE);
			if (der_len > 0) {
				return_code = CERT_PEM_FORMAT;
				if (NULL != cert_object) {
					new_cert = (DecodedCert *)LLSEC_calloc(1, sizeof(DecodedCert));
					if (NULL == new_cert) {
						return_code = J_MEMORY_ERROR;
					} else {
						/* Initialize the X509 certificate */
						wc_InitDecodedCert(new_cert, (byte const *)der_buffer, der_len, NULL);

						/* Parse the X509 DER certificate */
						if (NULL == check_error) {
							wolfcrypt_rc = wc_ParseCert(new_cert, TRUSTED_PEER_TYPE, NO_VERIFY, NULL);
						} else {
							wolfcrypt_rc = wc_ParseCert(new_cert, TRUSTED_PEER_TYPE, VERIFY, NULL);
							*check_error = wolfcrypt_rc;
						}

						if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
							*cert_object = new_cert;
						}
					}
				}
			} else {
				LLSEC_X509_DEBUG_TRACE("%s. wolfcrypt_x509_crt_parse(PEM) fail, return_code: %d\n", __func__,
				                       wolfcrypt_rc);
				return_code = J_CERT_PARSE_ERROR;
			}
			LLSEC_free(der_buffer);
		}
	}
	return return_code;
}

/**
 * @brief   Frees the resources and context associated of an Wolfcrypt public key structure.
 *
 * @param[in]  native_id  Reference to the public key structure
 *
 * @return     LLSEC_SUCCESS if the creation is successful,  LLSEC_ERROR otherwise.
 *
 */
static int32_t LLSEC_X509_CERT_wolfcrypt_close_key(int32_t native_id) {
	LLSEC_X509_DEBUG_TRACE("%s \n", __func__);
	int return_code = LLSEC_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_pub_key *key = (LLSEC_pub_key *)native_id;

	if (TYPE_RSA == key->key_type) {
		wc_FreeRsaKey((RsaKey *)key->key);
	} else {
		wc_ecc_free((ecc_key *)key->key);
	}

	LLSEC_free(key->key);
	LLSEC_free(key);
	return return_code;
}

// --------------------------------------------------------------------------------
// LLSEC_X509_CERT_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_X509_CERT_IMPL_parse(int8_t *cert, int32_t off, int32_t len) {
	LLSEC_X509_DEBUG_TRACE("%s(cert=%p, off=%d, len=%d)\n", __func__, cert, (int)off, (int)len);

	int32_t format = LLSEC_X509_UNKNOWN_FORMAT;
	int8_t *cert_data = &cert[off];
	format = get_x509_certificate_format(cert_data, len, NULL, NULL);

	return format;
}

// See the header file for the function documentation
int32_t LLSEC_X509_CERT_IMPL_get_x500_principal_data(int8_t *cert_data, int32_t cert_data_length,
                                                     uint8_t *principal_data, int32_t principal_data_length,
                                                     uint8_t get_issuer) {
	int32_t return_code = LLSEC_SUCCESS;
	int32_t format = LLSEC_X509_UNKNOWN_FORMAT;
	LLSEC_X509_DEBUG_TRACE("%s(cert=%p, Cert_len=%d,prin_len=%d,get_issuer=%d)\n", __func__, cert_data,
	                       (int)cert_data_length, (int)principal_data_length, (int)get_issuer);
	DecodedCert *certificate;
	format = get_x509_certificate_format(cert_data, cert_data_length, &certificate, NULL);
	if (NULL == certificate) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "Bad x509 certificate");
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		int len;

		if ((uint8_t)0 != get_issuer) {
			len = strlen(certificate->issuer);
		} else {
			len = strlen(certificate->subject);
		}

		if (len > principal_data_length) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Principal data buffer is too small");
			return_code = LLSEC_ERROR;
		} else {
			if ((uint8_t)0 != get_issuer) {
				len = strlen(certificate->issuer);
				(void)strncpy((char *)principal_data, certificate->issuer, principal_data_length);
			} else {
				len = strlen(certificate->subject);
				(void)strncpy((char *)principal_data, certificate->subject, principal_data_length);
			}
			wc_FreeDecodedCert(certificate);
			LLSEC_free(certificate);

			return_code = len;
		}
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_X509_CERT_IMPL_get_key(int8_t *cert_data, int32_t cert_data_length) {
	int32_t return_code = LLSEC_SUCCESS;
	DecodedCert *certificate;
	void *native_id = NULL;

	LLSEC_X509_DEBUG_TRACE("%s(cert=%p, len=%d)\n", __func__, cert_data, (int)cert_data_length);

	LLSEC_pub_key *pub_key = (LLSEC_pub_key *)LLSEC_calloc(1, sizeof(LLSEC_pub_key));
	if (NULL == pub_key) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "Can't allocate LLSEC_pub_key structure");
		return_code = LLSEC_ERROR;
	}

	if (LLSEC_SUCCESS == return_code) {
		(void)get_x509_certificate_format(cert_data, cert_data_length, &certificate, NULL);
		if (NULL == certificate) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Bad x509 certificate");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		// get public key len
		word32 pk_der_size = 0;
		byte *pk_der_buffer;
		// get needed buffer size
		wc_GetPubKeyDerFromCert(certificate, NULL, &pk_der_size);

		// allocate the public key buffer
		pk_der_buffer = LLSEC_calloc(pk_der_size, sizeof(byte));
		if (NULL == pk_der_buffer) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't allocate a public key DER buffer");
			return_code = LLSEC_ERROR;
		}
		if (LLSEC_SUCCESS == return_code) {
			int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
			// extract DER public key
			wolfcrypt_rc = wc_GetPubKeyDerFromCert(certificate, pk_der_buffer, &pk_der_size);
			if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
				(void)SNI_throwNativeException(LLSEC_ERROR, "Failed to extract DER public key!");
				return_code = LLSEC_ERROR;
			}

			if (LLSEC_SUCCESS == return_code) {
				// create the wolfcrypt key structure:
				word32 idx = 0;
				// try to parse an RSA key
				RsaKey *tmp_rsakey;
				tmp_rsakey = LLSEC_calloc(1, sizeof(RsaKey));
				if (NULL == tmp_rsakey) {
					(void)SNI_throwNativeException(LLSEC_ERROR, "Can't allocate RsaKey structure");
					return_code = LLSEC_ERROR;
				} else {
					wolfcrypt_rc = wc_InitRsaKey(tmp_rsakey, NULL);
					wolfcrypt_rc = wc_RsaPublicKeyDecode(pk_der_buffer, &idx, tmp_rsakey, pk_der_size);
					if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
						pub_key->key_type = TYPE_RSA;
						pub_key->key = (char *)tmp_rsakey;
					} else {
						wc_FreeRsaKey(tmp_rsakey);
						LLSEC_free(tmp_rsakey);
					}
				}
				if (NULL == pub_key->key) {
					// try to parse an EC key
					ecc_key *tmp_ecc_key;
					tmp_ecc_key = LLSEC_calloc(1, sizeof(ecc_key));
					if (NULL == tmp_ecc_key) {
						(void)SNI_throwNativeException(LLSEC_ERROR, "Can't allocate ecc_key structure");
						return_code = LLSEC_ERROR;
					} else {
						wolfcrypt_rc = wc_ecc_init(tmp_ecc_key);
						wolfcrypt_rc = wc_EccPublicKeyDecode(pk_der_buffer, &idx, tmp_ecc_key, pk_der_size);
						if (LLSEC_WOLFCRYPT_SUCCESS == wolfcrypt_rc) {
							pub_key->key_type = TYPE_ECDSA;
							pub_key->key = (char *)tmp_ecc_key;
						} else {
							wc_ecc_free(tmp_ecc_key);
							LLSEC_free(tmp_ecc_key);
						}
					}
				}
			}
		}

		if (NULL == pub_key->key) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Invalid public key from x509 certificate");
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		native_id = (void *)pub_key;
		if (SNI_OK != SNI_registerResource(native_id, (SNI_closeFunction)LLSEC_X509_CERT_wolfcrypt_close_key, NULL)) {
			(void)SNI_throwNativeException(LLSEC_ERROR, "Can't register SNI native resource");
			if (TYPE_RSA == pub_key->key_type) {
				wc_FreeRsaKey((RsaKey *)pub_key->key);
			} else {
				wc_ecc_free((ecc_key *)pub_key->key);
			}
			LLSEC_free(pub_key->key);
			return_code = LLSEC_ERROR;
		}
	}

	if (LLSEC_SUCCESS == return_code) {
		// cppcheck-suppress [misra-c2012-11.6] : Abstract data type for SNI usage
		return_code = (uint32_t)native_id;
	} else {
		if (NULL != certificate) {
			wc_FreeDecodedCert(certificate);
			LLSEC_free(certificate);
		}
		if (NULL != pub_key) {
			LLSEC_free(pub_key);
		}
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_X509_CERT_IMPL_verify(int8_t *cert_data, int32_t cert_data_length, int32_t public_key_id) {
	LLSEC_X509_DEBUG_TRACE("%s(cert=%p, len=%d, pubkey=%p)\n", __func__, cert_data, cert_data_length, public_key_id);
	LLSEC_UNUSED_PARAM(public_key_id);

	int return_code = LLSEC_SUCCESS;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_pub_key *key = (LLSEC_pub_key *)public_key_id;
	byte *key_buffer;
	word32 key_buffer_size;
	int pubKeyOID;

	// First, encode key into DER format (required by WolfCrypt certificate signature verification API)
	if (TYPE_RSA == key->key_type) {
		pubKeyOID = RSAk;
		wolfcrypt_rc = wc_RsaPublicKeyDerSize((RsaKey *)key->key, 1);
	} else { // ECDSA key type
		pubKeyOID = ECDSAk;
		key_buffer_size = wc_EccPublicKeyDerSize((ecc_key *)key->key, 1);
	}
	if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
		(void)SNI_throwNativeException(wolfcrypt_rc, "Could not encode public key: failed to calculate size");
		return_code = LLSEC_ERROR;
	}

	if (return_code == LLSEC_SUCCESS) {
		key_buffer = LLSEC_calloc(key_buffer_size, sizeof(byte));
		if (NULL == key_buffer) {
			(void)SNI_throwNativeException(-1, "Could not encode public key: not enough memory");
			return_code = LLSEC_ERROR;
		} else {
			if (TYPE_RSA == key->key_type) {
				wolfcrypt_rc = wc_RsaKeyToPublicDer((RsaKey *)key->key, key_buffer, key_buffer_size);
			} else { // ECDSA key type
				wolfcrypt_rc = wc_EccPublicKeyToDer((ecc_key *)key->key, key_buffer, key_buffer_size, 1);
			}
			if (LLSEC_WOLFCRYPT_SUCCESS > wolfcrypt_rc) {
				(void)SNI_throwNativeException(wolfcrypt_rc, "Could not encode public key");
				return_code = LLSEC_ERROR;
			}
		}
	}

	if (return_code == LLSEC_SUCCESS) {
		wolfcrypt_rc = wc_CheckCertSigPubKey((byte *)cert_data, cert_data_length, NULL, key_buffer, key_buffer_size,
		                                     pubKeyOID);
		if (LLSEC_WOLFCRYPT_SUCCESS != wolfcrypt_rc) {
			(void)SNI_throwNativeException(wolfcrypt_rc, "Certificate signature verification failed");
			return_code = LLSEC_ERROR;
		}
	}

	if (NULL != key_buffer) {
		LLSEC_free(key_buffer);
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_X509_CERT_IMPL_check_validity(int8_t *cert_data, int32_t cert_data_length) {
	LLSEC_X509_DEBUG_TRACE("%s \n", __func__);
	int return_code = LLSEC_SUCCESS;
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
			(void)SNI_throwNativeException(LLSEC_ERROR, "Bad x509 certificate");
			return_code = LLSEC_ERROR;
			break;
		}
	} else {
		return_code = J_SEC_NO_ERROR;
	}

	if (NULL != certificate) {
		wc_FreeDecodedCert(certificate);
		LLSEC_free(certificate);
	}

	return return_code;
}

// See the header file for the function documentation
int32_t LLSEC_X509_CERT_IMPL_get_close_key(void) {
	LLSEC_X509_DEBUG_TRACE("%s \n", __func__);
	return (int32_t)LLSEC_X509_CERT_wolfcrypt_close_key;
}
