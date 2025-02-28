/*
 * C
 *
 * Copyright 2023 MicroEJ Corp. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be found with this software.
 */

/**
 * @file
 * @brief MicroEJ Security low level API
 * @author MicroEJ Developer Team
 * @version 1.0.0
 */

// --------------------------------------------------------------------------------
// Includes
// --------------------------------------------------------------------------------

#include <LLSEC_SECRET_KEY_impl.h>
#include <LLSEC_wolfcrypt.h>

#include <string.h>

// --------------------------------------------------------------------------------
// LLSEC_SECRET_KEY_impl.h functions
// --------------------------------------------------------------------------------

// See the header file for the function documentation
int32_t LLSEC_SECRET_KEY_IMPL_get_encoded_max_size(int32_t native_id) {
	LLSEC_SECRET_KEY_DEBUG_TRACE("%s (native_id = %d)\n", __func__, (int)native_id);
	int32_t max_size = 0;

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_secret_key *secret_key = (LLSEC_secret_key *)native_id;
	if (NULL != secret_key) {
		max_size = secret_key->key_length;
	}

	LLSEC_SECRET_KEY_DEBUG_TRACE("%s Return size = %d\n", __func__, (int)max_size);
	return max_size;
}

// See the header file for the function documentation
int32_t LLSEC_SECRET_KEY_IMPL_get_encoded(int32_t native_id, uint8_t *output, int32_t output_length) {
	LLSEC_SECRET_KEY_DEBUG_TRACE("%s (native_id = %d)\n", __func__, (int)native_id);

	// cppcheck-suppress [misra-c2012-11.4] : Abstract data type for SNI usage
	LLSEC_secret_key *secret_key = (LLSEC_secret_key *)native_id;
	if (NULL != secret_key) {
		(void)memcpy(output, secret_key->key, output_length);
	}

	LLSEC_SECRET_KEY_DEBUG_TRACE("%s Return size = %d\n", __func__, (int)output_length);
	return output_length;
}
