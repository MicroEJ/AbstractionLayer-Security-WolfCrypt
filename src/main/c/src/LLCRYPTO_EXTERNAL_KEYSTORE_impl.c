/*
 * C
 *
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - External Key Store.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include "LLCRYPTO_common.h"
#include "LLCRYPTO_EXTERNAL_KEYSTORE_impl.h"
#include "bsp_util.h"

#include <sni.h>

// --------------------------------------------------------------------------------
// LLCRYPTO_EXTERNAL_KEYSTORE_impl.h functions
// --------------------------------------------------------------------------------

/*
 * This abstraction layer ships no key store: every native below is a weak stub that reports "Not implemented".
 * A VEE Port that holds a key store defines the same functions, which take precedence over these stubs.
 */

// Key Store Common Abstraction Layer API

BSP_DECLARE_WEAK_FCNT void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_login(jchar *password) {
	LLCRYPTO_UNUSED_PARAM(password);
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_size(void) {
	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getAlias(jint index, jbyte *alias) {
	LLCRYPTO_UNUSED_PARAM(index);
	LLCRYPTO_UNUSED_PARAM(alias);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jboolean LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_containsAlias(jbyte *alias) {
	LLCRYPTO_UNUSED_PARAM(alias);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return false;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getEntryType(jbyte *alias) {
	LLCRYPTO_UNUSED_PARAM(alias);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_deleteEntry(jbyte *alias) {
	LLCRYPTO_UNUSED_PARAM(alias);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

// Key Store Key Abstraction Layer API

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyId(jbyte *alias, jchar *password) {
	LLCRYPTO_UNUSED_PARAM(alias);
	LLCRYPTO_UNUSED_PARAM(password);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyType(jint keyId) {
	LLCRYPTO_UNUSED_PARAM(keyId);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyAlgorithm(jint keyId, jbyte *algorithm) {
	LLCRYPTO_UNUSED_PARAM(keyId);
	LLCRYPTO_UNUSED_PARAM(algorithm);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_openKeyEntryWithData(jbyte *alias, jbyte *key,
                                                                                jint chain_len) {
	LLCRYPTO_UNUSED_PARAM(alias);
	LLCRYPTO_UNUSED_PARAM(key);
	LLCRYPTO_UNUSED_PARAM(chain_len);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_openKeyEntryWithNativeId(jbyte *alias, jint key_id,
                                                                                    jchar *password, jint chain_len) {
	LLCRYPTO_UNUSED_PARAM(alias);
	LLCRYPTO_UNUSED_PARAM(key_id);
	LLCRYPTO_UNUSED_PARAM(password);
	LLCRYPTO_UNUSED_PARAM(chain_len);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_insertCertificateInChain(jint handle, jint index,
                                                                                    jbyte *certificate) {
	LLCRYPTO_UNUSED_PARAM(handle);
	LLCRYPTO_UNUSED_PARAM(index);
	LLCRYPTO_UNUSED_PARAM(certificate);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_closeKeyEntry(jint handle) {
	LLCRYPTO_UNUSED_PARAM(handle);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

// Key Store Certificate Abstraction Layer API

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateHandle(jbyte *alias) {
	LLCRYPTO_UNUSED_PARAM(alias);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateSize(jint handle) {
	LLCRYPTO_UNUSED_PARAM(handle);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateData(jint handle, jbyte *buffer) {
	LLCRYPTO_UNUSED_PARAM(handle);
	LLCRYPTO_UNUSED_PARAM(buffer);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_setCertificateEntry(jbyte *alias, jbyte *certificate) {
	LLCRYPTO_UNUSED_PARAM(alias);
	LLCRYPTO_UNUSED_PARAM(certificate);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

// Key Store Certificate Chain Abstraction Layer API

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChainHandle(jbyte *alias) {
	LLCRYPTO_UNUSED_PARAM(alias);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChainLength(jint handle) {
	LLCRYPTO_UNUSED_PARAM(handle);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateFromChain(jint handle, jint index) {
	LLCRYPTO_UNUSED_PARAM(handle);
	LLCRYPTO_UNUSED_PARAM(index);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_closeCertificateChainHandle(jint handle) {
	LLCRYPTO_UNUSED_PARAM(handle);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
