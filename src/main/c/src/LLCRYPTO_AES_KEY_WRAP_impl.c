/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 *
 * Build: 7E4D1F7C
 */

/**
 * @file
 * @brief LLCRYPTO implementation for WolfCrypt - AES Key Wrap.
 * @author MicroEJ Developer Team
 * @version 2.0.1
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include "LLCRYPTO_common.h"
#include "LLCRYPTO_AES_KEY_WRAP_impl.h"
#include "bsp_util.h"

#include <sni.h>

// --------------------------------------------------------------------------------
// LLCRYPTO_AES_KEY_WRAP_impl.h functions
// --------------------------------------------------------------------------------

BSP_DECLARE_WEAK_FCNT int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_get_transformation(uint8_t *transformation) {
	LLCRYPTO_UNUSED_PARAM(transformation);
	/* This lookup is the only entry point reached when the transformation is not supported at all. The refusal is
	 * returned rather than thrown: the Crypto library turns a returned error into the checked exception declared by
	 * Cipher.getInstance(), whereas a thrown one reaches the application as an unchecked native exception. The
	 * functions below are unreachable once this one refuses. */
	return LLCRYPTO_ERROR;
}

BSP_DECLARE_WEAK_FCNT int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_init(int32_t transformation_id, uint8_t is_decrypting,
                                                              int32_t secret_key_id) {
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	LLCRYPTO_UNUSED_PARAM(is_decrypting);
	LLCRYPTO_UNUSED_PARAM(secret_key_id);
	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");
	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_wrap(int32_t transformation_id, int32_t native_id,
                                                              int32_t key_id,
                                                              uint8_t *output,
                                                              int32_t output_offset, int32_t output_length,
                                                              uint8_t *algorithm) {
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	LLCRYPTO_UNUSED_PARAM(native_id);
	LLCRYPTO_UNUSED_PARAM(key_id);
	LLCRYPTO_UNUSED_PARAM(output);
	LLCRYPTO_UNUSED_PARAM(output_offset);
	LLCRYPTO_UNUSED_PARAM(output_length);
	LLCRYPTO_UNUSED_PARAM(algorithm);
	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");
	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_unwrap(int32_t transformation_id, int32_t native_id,
                                                                uint8_t *buffer,
                                                                int32_t buffer_offset, int32_t buffer_length,
                                                                uint8_t *algorithm) {
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	LLCRYPTO_UNUSED_PARAM(native_id);
	LLCRYPTO_UNUSED_PARAM(buffer);
	LLCRYPTO_UNUSED_PARAM(buffer_offset);
	LLCRYPTO_UNUSED_PARAM(buffer_length);
	LLCRYPTO_UNUSED_PARAM(algorithm);
	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");
	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT void LLCRYPTO_AES_KEY_WRAP_IMPL_close(int32_t transformation_id, int32_t native_id) {
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	LLCRYPTO_UNUSED_PARAM(native_id);
	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");
}

BSP_DECLARE_WEAK_FCNT int32_t LLCRYPTO_AES_KEY_WRAP_IMPL_get_close_id(int32_t transformation_id) {
	LLCRYPTO_UNUSED_PARAM(transformation_id);
	llcrypto_throw(LLCRYPTO_ERROR, "Not implemented");
	return SNI_IGNORED_RETURNED_VALUE;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
