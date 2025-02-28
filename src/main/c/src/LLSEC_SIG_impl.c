/*
 * Copyright 2024-2025 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - Signature.
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_ERRORS.h>
#include <LLSEC_SIG_impl.h>
#include <sni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "LLSEC_wolfcrypt.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

typedef struct LLSEC_SIG_algorithm LLSEC_SIG_algorithm;

struct LLSEC_SIG_algorithm {
	char *name;
	char *digest_name;
	char *oid;
	enum wc_HashType hash_type;
	enum wc_SignatureType sig_type;
	word32 key_len;
	LLSEC_pub_key_type key_type;
};

// --------------------------------------------------------------------------------
// Constant declarations
// --------------------------------------------------------------------------------

static LLSEC_SIG_algorithm available_sig_algorithms[2] = {
	{
		.name = "SHA256withRSA",
		.digest_name = "SHA-256",
		.oid = "1.2.840.113549.1.1.11",
		.hash_type = WC_HASH_TYPE_SHA256,
		.sig_type = WC_SIGNATURE_TYPE_RSA_W_ENC,
		.key_len = sizeof(RsaKey),
		.key_type = TYPE_RSA
	},
	{
		.name = "SHA256withECDSA",
		.digest_name = "SHA-256",
		.oid = "1.2.840.10045.4.3.2",
		.hash_type = WC_HASH_TYPE_SHA256,
		.sig_type = WC_SIGNATURE_TYPE_ECC,
		.key_len = sizeof(ecc_key),
		.key_type = TYPE_ECDSA
	}
};

// --------------------------------------------------------------------------------
// Private functions
// --------------------------------------------------------------------------------

static int llsec_sig_encodeDigestOid(uint8_t *out, enum wc_HashType hash_type, uint8_t *digest, int32_t digest_length);

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
static int llsec_sig_encodeDigestOid(uint8_t *out, enum wc_HashType hash_type, uint8_t *digest, int32_t digest_length) {
	int32_t ret = wc_HashGetOID(hash_type);
	int32_t encoded_length;
	if (ret < 0) {
		(void)SNI_throwNativeException(ret, "Could not retrieve the OID for this signature's digest algorithm");
		encoded_length = SNI_IGNORED_RETURNED_VALUE;
	} else {
		int oid = ret;
		LLSEC_SIG_DEBUG_TRACE("%s oid=%d\n", __func__, oid);
		ret = wc_EncodeSignature(out, digest, digest_length, oid);
		if (ret < 0) {
			(void)SNI_throwNativeException(ret,
			                               "Could not encode signature with the OID of this signature's digest algorithm");
			encoded_length = SNI_IGNORED_RETURNED_VALUE;
		} else {
			encoded_length = ret;
		}
	}
	LLSEC_SIG_DEBUG_TRACE("%s encoded_length=%d\n", __func__, encoded_length);
	return encoded_length;
}

// --------------------------------------------------------------------------------
// LLSEC_KEY_FACTORY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_SIG_IMPL_get_algorithm_description(uint8_t *algorithm_name, uint8_t *digest_algorithm_name,
                                                 int32_t digest_algorithm_name_length) {
	int32_t return_code = LLSEC_ERROR;
	LLSEC_SIG_DEBUG_TRACE("%s \n", __func__);

	int32_t nb_algorithms = sizeof(available_sig_algorithms) / sizeof(LLSEC_SIG_algorithm);
	LLSEC_SIG_algorithm *algorithm = &available_sig_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			(void)strncpy((char *)digest_algorithm_name, algorithm->digest_name, digest_algorithm_name_length);
			digest_algorithm_name[digest_algorithm_name_length - 1] = '\0'; // strncpy result may not be
			                                                                // null-terminated.
			// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
			return_code = (int32_t)algorithm;
			break;
		}
		algorithm++;
	}

	return return_code;
}

// See the header file for the function documentation
void LLSEC_SIG_IMPL_get_algorithm_oid(uint8_t *algorithm_name, uint8_t *oid, int32_t oid_length) {
	LLSEC_SIG_DEBUG_TRACE("%s \n", __func__);

	int32_t nb_algorithms = sizeof(available_sig_algorithms) / sizeof(LLSEC_SIG_algorithm);
	LLSEC_SIG_algorithm *algorithm = &available_sig_algorithms[0];

	while (--nb_algorithms >= 0) {
		if (0 == strcmp((char *)algorithm_name, algorithm->name)) {
			int32_t length = strlen(algorithm->oid);
			if ((length + 1) > oid_length) {
				(void)SNI_throwNativeException(-1, "Native oid length is bigger that the output byte array");
			} else {
				(void)strncpy((char *)oid, algorithm->oid, length);
				oid[length + 1] = '\0'; // strncpy result may not be null-terminated.
			}
			break;
		}
		algorithm++;
	}
	if (0 > nb_algorithms) {
		(void)SNI_throwNativeException(LLSEC_ERROR, "Algorithm not found");
	}
}

// See the header file for the function documentation
uint8_t LLSEC_SIG_IMPL_verify(int32_t algorithm_id, uint8_t *signature, int32_t signature_length, int32_t public_key_id,
                              uint8_t *digest, int32_t digest_length) {
	LLSEC_SIG_DEBUG_TRACE("%s \n", __func__);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_SIG_algorithm *algorithm = (LLSEC_SIG_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_pub_key *pub_key = (LLSEC_pub_key *)public_key_id;
	int8_t return_value = SNI_IGNORED_RETURNED_VALUE;
	int wolfcrypt_rc = LLSEC_WOLFCRYPT_SUCCESS;
	uint8_t *tmp_digest;
	uint32_t tmp_digest_length;

	if (pub_key->key_type != algorithm->key_type) {
		int32_t value = SNI_throwNativeException(-1, "Public key not compatible with signature algorithm");
	} else {
		// Workaround: https://github.com/wolfSSL/wolfssl/issues/5981
		uint8_t *encodedDigest = NULL;
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			encodedDigest = LLSEC_calloc(1, digest_length + MAX_DER_DIGEST_ASN_SZ);
			if (NULL == encodedDigest) {
				(void)SNI_throwNativeException(0, "Could not allocate buffer to encode digest");
				return_value = SNI_ERROR;
			} else {
				wolfcrypt_rc = llsec_sig_encodeDigestOid(encodedDigest, algorithm->hash_type, digest, digest_length);
				if (SNI_IGNORED_RETURNED_VALUE == wolfcrypt_rc) {
					LLSEC_free(encodedDigest);
					return_value = SNI_ERROR;
				} else {
					tmp_digest = encodedDigest;
					tmp_digest_length = wolfcrypt_rc;
				}
			}
		} else {
			tmp_digest = digest;
			tmp_digest_length = digest_length;
		}
		if (SNI_ERROR != return_value) {
			wolfcrypt_rc = wc_SignatureVerifyHash(algorithm->hash_type, algorithm->sig_type, tmp_digest,
			                                      tmp_digest_length, signature, signature_length, pub_key->key,
			                                      algorithm->key_len);

			if (NULL != encodedDigest) {
				LLSEC_free(encodedDigest);
			}

			if ((0 != wolfcrypt_rc) && (SIG_VERIFY_E != wolfcrypt_rc)) {
				(void)SNI_throwNativeException(wolfcrypt_rc, llsec_wc_error_message(wolfcrypt_rc));
				return_value = SNI_ERROR;
			} else {
				LLSEC_SIG_DEBUG_TRACE("%s ret=%d\n", __func__, wolfcrypt_rc);
				return_value = (0 == wolfcrypt_rc) ? JTRUE : JFALSE;
			}
		}
	}

	return return_value;
}

// See the header file for the function documentation
int32_t LLSEC_SIG_IMPL_sign(int32_t algorithm_id, uint8_t *signature, int32_t signature_length, int32_t private_key_id,
                            uint8_t *digest, int32_t digest_length) {
	LLSEC_SIG_DEBUG_TRACE("%s key=0x%x signature_length=%d digest_length=%d\n", __func__, private_key_id,
	                      signature_length, digest_length);
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_SIG_algorithm *algorithm = (LLSEC_SIG_algorithm *)algorithm_id;
	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_priv_key *priv_key = (LLSEC_priv_key *)private_key_id;
	int32_t return_code = SNI_IGNORED_RETURNED_VALUE;
	uint8_t *current_digest = digest;
	int32_t current_digest_length = digest_length;

	if (priv_key->key_type != algorithm->key_type) {
		(void)SNI_throwNativeException(0, "Private key not compatible with signature algorithm");
		return_code = SNI_IGNORED_RETURNED_VALUE;
	} else {
		// Workaround: https://github.com/wolfSSL/wolfssl/issues/5981
		uint8_t *encodedDigest = NULL;
		if (WC_SIGNATURE_TYPE_RSA_W_ENC == algorithm->sig_type) {
			encodedDigest = LLSEC_calloc(1, digest_length + MAX_DER_DIGEST_ASN_SZ);
			if (NULL == encodedDigest) {
				(void)SNI_throwNativeException(0, "Could not allocate buffer to encode digest");
				return_code = SNI_ERROR;
			} else {
				int ret = llsec_sig_encodeDigestOid(encodedDigest, algorithm->hash_type, digest, digest_length);
				if (SNI_isExceptionPending()) {
					LLSEC_free(encodedDigest);
					return_code = SNI_ERROR;
				} else {
					current_digest = encodedDigest;
					current_digest_length = ret;
				}
			}
		}
		if (SNI_ERROR != return_code) {
			// TODO: check if we should use wc_SignatureGenerateHash_ex(verify = false)
			int ret = wc_SignatureGenerateHash(algorithm->hash_type, algorithm->sig_type, current_digest,
			                                   current_digest_length, signature, (word32 *)&signature_length,
			                                   priv_key->key, algorithm->key_len, llsec_wc_RNG);

			if (NULL != encodedDigest) {
				LLSEC_free(encodedDigest);
			}

			if (0 != ret) {
				(void)SNI_throwNativeException(ret, llsec_wc_error_message(ret));
			} else {
				LLSEC_SIG_DEBUG_TRACE("%s signature_length=%d\n", __func__, signature_length);
				return_code = signature_length;
			}
		} else {
			return_code = SNI_IGNORED_RETURNED_VALUE;
		}
	}
	return return_code;
}
