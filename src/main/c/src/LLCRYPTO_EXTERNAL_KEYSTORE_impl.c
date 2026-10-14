/*
 * C
 *
 * Copyright 2025-2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - Digest.
 * @author MicroEJ Developer Team
 * @version 2.0.0
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

BSP_DECLARE_WEAK_FCNT void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_login(jchar *password) {
	(void)password;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyId(jbyte *alias, jchar *password) {
	(void)(password);
	(void)(alias);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyType(jint keyId) {
	(void)(keyId);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT void LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getKeyAlgorithm(jint keyId, jbyte *algorithm) {
	(void)(keyId);
	(void)(algorithm);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificate(jbyte *alias,
                                                                          jbyte **cert_buf, jint *cert_size) {
	(void)(alias);
	(void)(cert_buf);
	(void)(cert_size);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChainHandle(jbyte *alias) {
	(void)(alias);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getCertificateChain(jint handle,
                                                                               jbyte **cert_buf, jint *cert_size) {
	(void)(handle);
	(void)(cert_buf);
	(void)(cert_size);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_size(void) {
	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jint LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_getAlias(jint index, jbyte *alias) {
	(void)(index);
	(void)(alias);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT jboolean LLCRYPTO_EXTERNAL_KEYSTORE_IMPL_containsAlias(jbyte *alias) {
	(void)(alias);

	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");

	return false;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
