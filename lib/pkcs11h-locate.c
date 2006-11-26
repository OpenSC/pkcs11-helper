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

#include "common.h"

#if defined(ENABLE_PKCS11H_LOCATE)

#include <pkcs11-helper-1.0/pkcs11h-token.h>
#include <pkcs11-helper-1.0/pkcs11h-locate.h>
#include "_pkcs11h-mem.h"
#include "_pkcs11h-crypto.h"
#include "_pkcs11h-util.h"
#include "_pkcs11h-session.h"
#include "_pkcs11h-token.h"
#include "_pkcs11h-certificate.h"

static
CK_RV
_pkcs11h_locate_getTokenIdBySlotId (
	IN const char * const slot,
	OUT pkcs11h_token_id_t * const p_token_id
);

static
CK_RV
_pkcs11h_locate_getTokenIdBySlotName (
	IN const char * const name,
	OUT pkcs11h_token_id_t * const p_token_id
);

static
CK_RV
_pkcs11h_locate_getTokenIdByLabel (
	IN const char * const label,
	OUT pkcs11h_token_id_t * const p_token_id
);

#if defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_locate_getCertificateIdByLabel (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const label
);
static
CK_RV
_pkcs11h_locate_getCertificateIdBySubject (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const subject
);

#endif				/* ENABLE_PKCS11H_CERTIFICATE */
#if defined(ENABLE_PKCS11H_TOKEN) || defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_locate_getTokenIdBySlotId (
	IN const char * const slot,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_provider_t current_provider = NULL;
	char reference[sizeof (((pkcs11h_provider_t)NULL)->reference)];

	CK_SLOT_ID selected_slot = PKCS11H_INVALID_SLOT_ID;
	CK_TOKEN_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (slot!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotId entry slot='%s', p_token_id=%p",
		slot,
		(void *)p_token_id
	);

	*p_token_id = NULL;

	if (rv == CKR_OK) {
		if (strchr (slot, ':') == NULL) {
			reference[0] = '\0';
			selected_slot = atol (slot);
		}
		else {
			char *p;

			strncpy (reference, slot, sizeof (reference));
			reference[sizeof (reference)-1] = '\0';

			p = strchr (reference, ':');

			*p = '\0';
			p++;
			selected_slot = atol (p);
		}
	}
	
	if (rv == CKR_OK) {
		current_provider=g_pkcs11h_data->providers;
		while (
			current_provider != NULL &&
			reference[0] != '\0' &&		/* So first provider will be selected */
			strcmp (current_provider->reference, reference)
		) {
			current_provider = current_provider->next;
		}
	
		if (
			current_provider == NULL ||
			(
				current_provider != NULL &&
				!current_provider->enabled
			)
		) {
			rv = CKR_SLOT_ID_INVALID;
		}
	}

	if (
		rv == CKR_OK &&
		(rv = current_provider->f->C_GetTokenInfo (selected_slot, &info)) == CKR_OK
	) {
		rv = _pkcs11h_token_getTokenId (
			&info,
			p_token_id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotId return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

static
CK_RV
_pkcs11h_locate_getTokenIdBySlotName (
	IN const char * const name,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_provider_t current_provider = NULL;

	CK_SLOT_ID selected_slot = PKCS11H_INVALID_SLOT_ID;
	CK_TOKEN_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL found = FALSE;

	PKCS11H_ASSERT (name!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotName entry name='%s', p_token_id=%p",
		name,
		(void *)p_token_id
	);

	*p_token_id = NULL;

	current_provider = g_pkcs11h_data->providers;
	while (
		current_provider != NULL &&
		rv == CKR_OK &&
		!found
	) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;

		if (!current_provider->enabled) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getSlotList (
				current_provider,
				CK_TRUE,
				&slots,
				&slotnum
			);
		}

		for (
			slot_index=0;
			(
				slot_index < slotnum &&
				rv == CKR_OK &&
				!found
			);
			slot_index++
		) {
			CK_SLOT_INFO info;

			if (
				(rv = current_provider->f->C_GetSlotInfo (
					slots[slot_index],
					&info
				)) == CKR_OK
			) {
				char current_name[sizeof (info.slotDescription)+1];

				_pkcs11h_util_fixupFixedString (
					current_name,
					(char *)info.slotDescription,
					sizeof (info.slotDescription)
				);

				if (!strcmp (current_name, name)) {
					found = TRUE;
					selected_slot = slots[slot_index];
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get slot information for provider '%s' slot %ld rv=%ld-'%s'",
					current_provider->manufacturerID,
					slots[slot_index],
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
				current_provider->manufacturerID,
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		if (slots != NULL) {
			_pkcs11h_mem_free ((void *)&slots);
			slots = NULL;
		}

		if (!found) {
			current_provider = current_provider->next;
		}
	}

	if (rv == CKR_OK && !found) {
		rv = CKR_SLOT_ID_INVALID;
	}

	if (
		rv == CKR_OK &&
		(rv = current_provider->f->C_GetTokenInfo (selected_slot, &info)) == CKR_OK
	) {
		rv = _pkcs11h_token_getTokenId (
			&info,
			p_token_id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdBySlotName return rv=%ld-'%s' *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv; 
}

static
CK_RV
_pkcs11h_locate_getTokenIdByLabel (
	IN const char * const label,
	OUT pkcs11h_token_id_t * const p_token_id
) {
	pkcs11h_provider_t current_provider = NULL;

	CK_SLOT_ID selected_slot = PKCS11H_INVALID_SLOT_ID;
	CK_TOKEN_INFO info;
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL found = FALSE;

	PKCS11H_ASSERT (label!=NULL);
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdByLabel entry label='%s', p_token_id=%p",
		label,
		(void *)p_token_id
	);

	*p_token_id = NULL;

	current_provider = g_pkcs11h_data->providers;
	while (
		current_provider != NULL &&
		rv == CKR_OK &&
		!found
	) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;

		if (!current_provider->enabled) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		}

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getSlotList (
				current_provider,
				CK_TRUE,
				&slots,
				&slotnum
			);
		}

		for (
			slot_index=0;
			(
				slot_index < slotnum &&
				rv == CKR_OK &&
				!found
			);
			slot_index++
		) {
			CK_TOKEN_INFO info;

			if (rv == CKR_OK) {
				rv = current_provider->f->C_GetTokenInfo (
					slots[slot_index],
					&info
				);
			}

			if (rv == CKR_OK) {
				char current_label[sizeof (info.label)+1];
		
				_pkcs11h_util_fixupFixedString (
					current_label,
					(char *)info.label,
					sizeof (info.label)
				);

				if (!strcmp (current_label, label)) {
					found = TRUE;
					selected_slot = slots[slot_index];
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get token information for provider '%s' slot %ld rv=%ld-'%s'",
					current_provider->manufacturerID,
					slots[slot_index],
					rv,
					pkcs11h_getMessage (rv)
				);

				/*
				 * Ignore error
				 */
				rv = CKR_OK;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%ld-'%s'",
				current_provider->manufacturerID,
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		if (slots != NULL) {
			_pkcs11h_mem_free ((void *)&slots);
			slots = NULL;
		}

		if (!found) {
			current_provider = current_provider->next;
		}
	}

	if (rv == CKR_OK && !found) {
		rv = CKR_SLOT_ID_INVALID;
	}

	if (
		rv == CKR_OK &&
		(rv = current_provider->f->C_GetTokenInfo (selected_slot, &info)) == CKR_OK
	) {
		rv = _pkcs11h_token_getTokenId (
			&info,
			p_token_id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getTokenIdByLabel return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

CK_RV
pkcs11h_locate_token (
	IN const char * const slot_type,
	IN const char * const slot,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_token_id_t * const p_token_id
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif

	pkcs11h_token_id_t dummy_token_id = NULL;
	pkcs11h_token_id_t token_id = NULL;
	PKCS11H_BOOL found = FALSE;
	
	CK_RV rv = CKR_OK;

	unsigned nRetry = 0;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (slot_type!=NULL);
	PKCS11H_ASSERT (slot!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	PKCS11H_ASSERT (p_token_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locate_token entry slot_type='%s', slot='%s', user_data=%p, p_token_id=%p",
		slot_type,
		slot,
		user_data,
		(void *)p_token_id
	);

	*p_token_id = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&g_pkcs11h_data->mutexes.global)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_token_newTokenId (&dummy_token_id)) == CKR_OK
	) {
		/*
		 * Temperary slot id
		 */
		strcpy (dummy_token_id->display, "SLOT(");
		strncat (dummy_token_id->display, slot_type, sizeof (dummy_token_id->display)-1-strlen (dummy_token_id->display));
		strncat (dummy_token_id->display, "=", sizeof (dummy_token_id->display)-1-strlen (dummy_token_id->display));
		strncat (dummy_token_id->display, slot, sizeof (dummy_token_id->display)-1-strlen (dummy_token_id->display));
		strncat (dummy_token_id->display, ")", sizeof (dummy_token_id->display)-1-strlen (dummy_token_id->display));
		dummy_token_id->display[sizeof (dummy_token_id->display)-1] = 0;
	}

	while (rv == CKR_OK && !found) {
		if (!strcmp (slot_type, "id")) {
			rv = _pkcs11h_locate_getTokenIdBySlotId (
				slot,
				&token_id
			);
		}
		else if (!strcmp (slot_type, "name")) {
			rv = _pkcs11h_locate_getTokenIdBySlotName (
				slot,
				&token_id
			);
		}
		else if (!strcmp (slot_type, "label")) {
			rv = _pkcs11h_locate_getTokenIdByLabel (
				slot,
				&token_id
			);
		}
		else {
			rv = CKR_ARGUMENTS_BAD;
		}

		if (rv == CKR_OK) {
			found = TRUE;
		}

		/*
		 * Ignore error, since we have what we
		 * want in found.
		 */
		if (rv != CKR_OK && rv != CKR_ARGUMENTS_BAD) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: pkcs11h_locate_token failed rv=%ld-'%s'",
				rv,
				pkcs11h_getMessage (rv)
			);

			rv = CKR_OK;
		}

		if (rv == CKR_OK && !found && (mask_prompt & PKCS11H_PROMPT_MASK_ALLOW_TOKEN_PROMPT) == 0) {
			rv = CKR_TOKEN_NOT_PRESENT;
		}

		if (rv == CKR_OK && !found) {

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Calling token_prompt hook for '%s'",
				dummy_token_id->display
			);
	
			if (
				!g_pkcs11h_data->hooks.token_prompt (
					g_pkcs11h_data->hooks.token_prompt_data,
					user_data,
					dummy_token_id,
					nRetry++
				)
			) {
				rv = CKR_CANCEL;
			}

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: token_prompt returned %ld",
				rv
			);
		}
	}

	if (rv == CKR_OK && !found) {
		rv = CKR_SLOT_ID_INVALID;
	}

	if (rv == CKR_OK) {
		*p_token_id = token_id;
		token_id = NULL;
	}

	if (dummy_token_id != NULL) {
		pkcs11h_token_freeTokenId (dummy_token_id);
		dummy_token_id = NULL;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&g_pkcs11h_data->mutexes.global);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locate_token return rv=%ld-'%s', *p_token_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_token_id
	);

	return rv;
}

#endif				/* ENABLE_PKCS11H_TOKEN || ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

static
CK_RV
_pkcs11h_locate_getCertificateIdByLabel (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const label
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)},
		{CKA_LABEL, (CK_BYTE_PTR)label, strlen (label)}
	};

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;

	CK_ULONG i;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (certificate_id!=NULL);
	PKCS11H_ASSERT (label!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdByLabel entry session=%p, certificate_id=%p, label='%s'",
		(void *)session,
		(void *)certificate_id,
		label
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_validate (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_findObjects (
			session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	for (i=0;rv == CKR_OK && i < objects_found;i++) {
		CK_ATTRIBUTE attrs[] = {
			{CKA_ID, NULL, 0},
			{CKA_VALUE, NULL, 0}
		};

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getObjectAttributes (
				session,
				objects[i],
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);
		}

		if (
			rv == CKR_OK &&
			_pkcs11h_certificate_isBetterCertificate (
				certificate_id->certificate_blob,
				certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			)
		) {
			if (certificate_id->attrCKA_ID != NULL) {
				_pkcs11h_mem_free ((void *)&certificate_id->attrCKA_ID);
			}
			if (certificate_id->certificate_blob != NULL) {
				_pkcs11h_mem_free ((void *)&certificate_id->certificate_blob);
			}
			rv = _pkcs11h_mem_duplicate (
				(void *)&certificate_id->attrCKA_ID,
				&certificate_id->attrCKA_ID_size,
				attrs[0].pValue,
				attrs[0].ulValueLen
			);
			rv = _pkcs11h_mem_duplicate (
				(void *)&certificate_id->certificate_blob,
				&certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			);
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%ld-'%s'",
				session->provider->manufacturerID,
				objects[i],
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		_pkcs11h_session_freeObjectAttributes (
			attrs,
			sizeof (attrs) / sizeof (CK_ATTRIBUTE)
		);
	}
	
	if (
		rv == CKR_OK &&
		certificate_id->certificate_blob == NULL
	) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (objects != NULL) {
		_pkcs11h_mem_free ((void *)&objects);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	/*
	 * No need to free allocated objects
	 * on error, since the certificate_id
	 * should be free by caller.
	 */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdByLabel return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
_pkcs11h_locate_getCertificateIdBySubject (
	IN const pkcs11h_session_t session,
	IN OUT const pkcs11h_certificate_id_t certificate_id,
	IN const char * const subject
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)}
	};

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;

	CK_ULONG i;

	PKCS11H_ASSERT (session!=NULL);
	PKCS11H_ASSERT (certificate_id!=NULL);
	PKCS11H_ASSERT (subject!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdBySubject entry session=%p, certificate_id=%p, subject='%s'",
		(void *)session,
		(void *)certificate_id,
		subject
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_validate (session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_findObjects (
			session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	for (i=0;rv == CKR_OK && i < objects_found;i++) {
		CK_ATTRIBUTE attrs[] = {
			{CKA_ID, NULL, 0},
			{CKA_VALUE, NULL, 0}
		};
		char current_subject[1024];
		current_subject[0] = '\0';

		if (rv == CKR_OK) {
			rv = _pkcs11h_session_getObjectAttributes (
				session,
				objects[i],
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);
		}

		if (
			rv == CKR_OK &&
			!g_pkcs11h_crypto_engine.certificate_get_dn (
				g_pkcs11h_crypto_engine.global_data,
				attrs[1].pValue,
				attrs[1].ulValueLen,
				current_subject,
				sizeof (current_subject)
			)
		) {
			rv = CKR_FUNCTION_FAILED;
		}

		if (
			rv == CKR_OK &&
			!strcmp (subject, current_subject) &&
			_pkcs11h_certificate_isBetterCertificate (
				certificate_id->certificate_blob,
				certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			)
		) {
			if (certificate_id->attrCKA_ID != NULL) {
				_pkcs11h_mem_free ((void *)&certificate_id->attrCKA_ID);
			}
			if (certificate_id->certificate_blob != NULL) {
				_pkcs11h_mem_free ((void *)&certificate_id->certificate_blob);
			}
			rv = _pkcs11h_mem_duplicate (
				(void *)&certificate_id->attrCKA_ID,
				&certificate_id->attrCKA_ID_size,
				attrs[0].pValue,
				attrs[0].ulValueLen
			);
			rv = _pkcs11h_mem_duplicate (
				(void *)&certificate_id->certificate_blob,
				&certificate_id->certificate_blob_size,
				attrs[1].pValue,
				attrs[1].ulValueLen
			);
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%ld-'%s'",
				session->provider->manufacturerID,
				objects[i],
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}

		_pkcs11h_session_freeObjectAttributes (
			attrs,
			sizeof (attrs) / sizeof (CK_ATTRIBUTE)
		);
	}
	
	if (
		rv == CKR_OK &&
		certificate_id->certificate_blob == NULL
	) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (objects != NULL) {
		_pkcs11h_mem_free ((void *)&objects);
	}

	/*
	 * No need to free allocated objects
	 * on error, since the certificate_id
	 * should be free by caller.
	 */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_locate_getCertificateIdBySubject return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_locate_certificate (
	IN const char * const slot_type,
	IN const char * const slot,
	IN const char * const id_type,
	IN const char * const id,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_certificate_id_t * const p_certificate_id
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_certificate_id_t certificate_id = NULL;
	pkcs11h_session_t session = NULL;
	PKCS11H_BOOL op_succeed = FALSE;
	PKCS11H_BOOL login_retry = FALSE;
	
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (slot_type!=NULL);
	PKCS11H_ASSERT (slot!=NULL);
	PKCS11H_ASSERT (id_type!=NULL);
	PKCS11H_ASSERT (id!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	PKCS11H_ASSERT (p_certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locateCertificate entry slot_type='%s', slot='%s', id_type='%s', id='%s', user_data=%p, mask_prompt=%08x, p_certificate_id=%p",
		slot_type,
		slot,
		id_type,
		id,
		user_data,
		mask_prompt,
		(void *)p_certificate_id
	);

	*p_certificate_id = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_certificate_newCertificateId (&certificate_id);
	}

	if (rv == CKR_OK) {
		rv = pkcs11h_locate_token (
			slot_type,
			slot,
			user_data,
			mask_prompt,
			&certificate_id->token_id
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_getSessionByTokenId (
			certificate_id->token_id,
			&session
		);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&g_pkcs11h_data->mutexes.global)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	while (rv == CKR_OK && !op_succeed) {
		if (!strcmp (id_type, "id")) {
			certificate_id->attrCKA_ID_size = strlen (id)/2;

			if (certificate_id->attrCKA_ID_size == 0) {
				rv = CKR_FUNCTION_FAILED;
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_mem_malloc (
					(void*)&certificate_id->attrCKA_ID,
					certificate_id->attrCKA_ID_size
				)) == CKR_OK
			) {
				_pkcs11h_util_hexToBinary (
					certificate_id->attrCKA_ID,
					id,
					&certificate_id->attrCKA_ID_size
				);
			}
		}
		else if (!strcmp (id_type, "label")) {
			rv = _pkcs11h_locate_getCertificateIdByLabel (
				session,
				certificate_id,
				id
			);
		}
		else if (!strcmp (id_type, "subject")) {
			rv = _pkcs11h_locate_getCertificateIdBySubject (
				session,
				certificate_id,
				id
			);
		}
		else {
			rv = CKR_ARGUMENTS_BAD;
		}

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Get certificate failed: %ld:'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);

				rv = _pkcs11h_session_login (
					session,
					TRUE,
					TRUE,
					user_data,
					mask_prompt
				);

				login_retry = TRUE;
			}
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&g_pkcs11h_data->mutexes.global);
		mutex_locked = FALSE;
	}
#endif

	if (rv == CKR_OK) {
		*p_certificate_id = certificate_id;
		certificate_id = NULL;
	}

	if (certificate_id != NULL) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}

	if (session != NULL) {
		_pkcs11h_session_release (session);
		session = NULL;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_locateCertificate return rv=%ld-'%s' *p_certificate_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_certificate_id
	);
	
	return rv;
}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

#endif				/* ENABLE_PKCS11H_LOCATE */

