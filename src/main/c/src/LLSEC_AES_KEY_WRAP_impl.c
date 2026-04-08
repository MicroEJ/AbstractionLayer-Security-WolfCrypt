/*
 * C
 *
 * Copyright 2026 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief LLSECURITY implementation for WolfCrypt - AES Key Wrap.
 * @author MicroEJ Developer Team
 * @version 1.1.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include "LLSEC_common.h"
#include "LLSEC_AES_KEY_WRAP_impl.h"
#include "bsp_util.h"

#include <sni.h>

// --------------------------------------------------------------------------------
// LLSEC_AES_KEY_WRAP_impl.h functions
// --------------------------------------------------------------------------------

BSP_DECLARE_WEAK_FCNT int32_t LLSEC_AES_KEY_WRAP_IMPL_get_transformation(uint8_t *transformation) {
	LLSEC_UNUSED_PARAM(transformation);
	llsec_throw(LLSEC_ERROR, "Not implemented");
	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT int32_t LLSEC_AES_KEY_WRAP_IMPL_init(int32_t transformation_id, uint8_t is_decrypting,
                                                           int32_t secret_key_id) {
	LLSEC_UNUSED_PARAM(transformation_id);
	LLSEC_UNUSED_PARAM(is_decrypting);
	LLSEC_UNUSED_PARAM(secret_key_id);
	llsec_throw(LLSEC_ERROR, "Not implemented");
	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT int32_t LLSEC_AES_KEY_WRAP_IMPL_wrap(int32_t transformation_id, int32_t native_id, int32_t key_id,
                                                           uint8_t *output,
                                                           int32_t output_offset, int32_t output_length,
                                                           uint8_t *algorithm) {
	LLSEC_UNUSED_PARAM(transformation_id);
	LLSEC_UNUSED_PARAM(native_id);
	LLSEC_UNUSED_PARAM(key_id);
	LLSEC_UNUSED_PARAM(output);
	LLSEC_UNUSED_PARAM(output_offset);
	LLSEC_UNUSED_PARAM(output_length);
	LLSEC_UNUSED_PARAM(algorithm);
	llsec_throw(LLSEC_ERROR, "Not implemented");
	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT int32_t LLSEC_AES_KEY_WRAP_IMPL_unwrap(int32_t transformation_id, int32_t native_id,
                                                             uint8_t *buffer,
                                                             int32_t buffer_offset, int32_t buffer_length,
                                                             uint8_t *algorithm) {
	LLSEC_UNUSED_PARAM(transformation_id);
	LLSEC_UNUSED_PARAM(native_id);
	LLSEC_UNUSED_PARAM(buffer);
	LLSEC_UNUSED_PARAM(buffer_offset);
	LLSEC_UNUSED_PARAM(buffer_length);
	LLSEC_UNUSED_PARAM(algorithm);
	llsec_throw(LLSEC_ERROR, "Not implemented");
	return SNI_IGNORED_RETURNED_VALUE;
}

BSP_DECLARE_WEAK_FCNT void LLSEC_AES_KEY_WRAP_IMPL_close(int32_t transformation_id, int32_t native_id) {
	LLSEC_UNUSED_PARAM(transformation_id);
	LLSEC_UNUSED_PARAM(native_id);
	llsec_throw(LLSEC_ERROR, "Not implemented");
}

BSP_DECLARE_WEAK_FCNT int32_t LLSEC_AES_KEY_WRAP_IMPL_get_close_id(int32_t transformation_id) {
	LLSEC_UNUSED_PARAM(transformation_id);
	llsec_throw(LLSEC_ERROR, "Not implemented");
	return SNI_IGNORED_RETURNED_VALUE;
}

// -----------------------------------------------------------------------------
// EOF
// -----------------------------------------------------------------------------
