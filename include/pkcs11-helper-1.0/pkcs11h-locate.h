/*
 * Copyright (c) 2005-2006 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, or the OpenIB.org BSD license.
 *
 * GNU General Public License (GPL) Version 2
 * ===========================================
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING.GPL included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * OpenIB.org BSD license
 * =======================
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *   o  Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   o  Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *   o  The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file pkcs11h-locate.h
 * @brief pkcs11-helper locate interface.
 * @author Alon Bar-Lev <alon.barlev@gmail.com>
 */

#ifndef __PKCS11H_LOCATE_H
#define __PKCS11H_LOCATE_H

#include <pkcs11-helper-1.0/pkcs11h-core.h>
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Locate token based on atributes.
 * @param slot_type		How to locate slot.
 * @param slot			Slot name.
 * @param user_data		Optional user data, to be passed to hooks.
 * @param mask_prompt		Allow prompt @ref PKCS11H_PROMPT_MASK.
 * @param p_token_id		Token object.
 * @note Caller must free result.
 * @see pkcs11h_token_freeTokenId().
 * @remarks
 * Slot:
 * 	- id		- Slot number.
 * 	- name		- Slot name.
 * 	- label		- Available token label.
 */
CK_RV
pkcs11h_locate_token (
	IN const char * const slot_type,
	IN const char * const slot,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_token_id_t * const p_token_id
);

/**
 * @brief Locate certificate based on atributes.
 * @param slot_type		How to locate slot.
 * @param slot			Slot name.
 * @param id_type		How to locate object.
 * @param id			Object name.
 * @param user_data		Optional user data, to be passed to hooks.
 * @param mask_prompt		Allow prompt @ref PKCS11H_PROMPT_MASK.
 * @param p_certificate_id	Certificate object.
 * @note Caller must free result.
 * @see pkcs11h_certificate_freeCertificateId().
 * @remarks
 * Slot:
 *	Same as in @ref pkcs11h_locate_token().
 * @remarks
 * Object:
 * 	- id		- Certificate CKA_ID (hex string) (Fastest).
 * 	- label		- Certificate CKA_LABEL (string).
 * 	- subject	- Certificate subject (OpenSSL or GNUTLS DN).
 */
CK_RV
pkcs11h_locate_certificate (
	IN const char * const slot_type,
	IN const char * const slot,
	IN const char * const id_type,
	IN const char * const id,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_certificate_id_t * const p_certificate_id
);

#ifdef __cplusplus
}
#endif

#endif				/* __PKCS11H_LOCATE_H */
