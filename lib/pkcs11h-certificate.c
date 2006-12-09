/*
 * Copyright (c) 2005-2006 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, or the BSD license.
 *
 * GNU General Public License (GPL) Version 2
 * ===========================================
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING.GPL included with this
 * distribution); if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * BSD License
 * ============
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     o Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     o Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     o Neither the name of the <ORGANIZATION> nor the names of its
 *       contributors may be used to endorse or promote products derived from
 *       this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"

#if defined(ENABLE_PKCS11H_CERTIFICATE)

#include <pkcs11-helper-1.0/pkcs11h-token.h>
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#include "_pkcs11h-mem.h"
#include "_pkcs11h-sys.h"
#include "_pkcs11h-crypto.h"
#include "_pkcs11h-session.h"
#include "_pkcs11h-token.h"
#include "_pkcs11h-certificate.h"

enum _pkcs11h_private_op_e {
	_pkcs11h_private_op_sign=0,
	_pkcs11h_private_op_sign_recover,
	_pkcs11h_private_op_decrypt,
	_pkcs11h_private_op_unwrap
};

static
CK_RV
__pkcs11h_certificate_doPrivateOperation (
	IN const pkcs11h_certificate_t certificate,
	IN const enum _pkcs11h_private_op_e op,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
);

static
CK_RV
__pkcs11h_certificate_loadCertificate (
	IN const pkcs11h_certificate_t certificate
);

static
CK_RV
__pkcs11h_certificate_updateCertificateIdDescription (
	IN OUT pkcs11h_certificate_id_t certificate_id
);

static
CK_RV
__pkcs11h_certificate_getKeyAttributes (
	IN const pkcs11h_certificate_t certificate
);

static
CK_RV
__pkcs11h_certificate_splitCertificateIdList (
	IN const pkcs11h_certificate_id_list_t cert_id_all,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
);

PKCS11H_BOOL
_pkcs11h_certificate_isBetterCertificate (
	IN const unsigned char * const current,
	IN const size_t current_size,
	IN const unsigned char * const newone,
	IN const size_t newone_size
) {
	PKCS11H_BOOL is_better = FALSE;

	/*PKCS11H_ASSERT (current!=NULL); NOT NEEDED */
	PKCS11H_ASSERT (newone!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_isBetterCertificate entry current=%p, current_size=%u, newone=%p, newone_size=%u",
		current,
		current_size,
		newone,
		newone_size
	);

	/*
	 * First certificae
	 * always select
	 */
	if (current_size == 0 || current == NULL) {
		is_better = TRUE;
	}
	else {
		time_t notAfterCurrent, notAfterNew;

		if (
			!g_pkcs11h_crypto_engine.certificate_get_expiration (
				g_pkcs11h_crypto_engine.global_data,
				current,
				current_size,
				&notAfterCurrent
			)
		) {
			notAfterCurrent = (time_t)0;
		}

		if (
			!g_pkcs11h_crypto_engine.certificate_get_expiration (
				g_pkcs11h_crypto_engine.global_data,
				newone,
				newone_size,
				&notAfterNew
			)
		) {
			notAfterCurrent = (time_t)0;
		}

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: _pkcs11h_certificate_isBetterCertificate notAfterCurrent='%s', notAfterNew='%s'",
			asctime (localtime (&notAfterCurrent)),
			asctime (localtime (&notAfterNew))
		);

		is_better = notAfterNew > notAfterCurrent;
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_isBetterCertificate return is_better=%d",
		is_better ? 1 : 0
	);
	
	return is_better;
}

CK_RV
_pkcs11h_certificate_newCertificateId (
	OUT pkcs11h_certificate_id_t * const p_certificate_id
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (p_certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_newCertificateId entry p_certificate_id=%p",
		(void *)p_certificate_id
	);

	*p_certificate_id = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_malloc ((void *)p_certificate_id, sizeof (struct pkcs11h_certificate_id_s));
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_newCertificateId return rv=%lu-'%s', *p_certificate_id=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_certificate_id
	);

	return rv;
}

static
CK_RV
__pkcs11h_certificate_loadCertificate (
	IN const pkcs11h_certificate_t certificate
) {
	/*
	 * THREADING:
	 * certificate->mutex must be locked
	 */
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
	CK_ATTRIBUTE cert_filter[] = {
		{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)},
		{CKA_ID, NULL, 0}
	};

	CK_OBJECT_HANDLE *objects = NULL;
	CK_ULONG objects_found = 0;
	CK_RV rv = CKR_OK;

	CK_ULONG i;

	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (certificate->id!=NULL);
	
	/* Must be after assert */
	cert_filter[1].pValue = certificate->id->attrCKA_ID;
	cert_filter[1].ulValueLen = certificate->id->attrCKA_ID_size;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_certificate_loadCertificate entry certificate=%p",
		(void *)certificate
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_validate (certificate->session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_findObjects (
			certificate->session,
			cert_filter,
			sizeof (cert_filter) / sizeof (CK_ATTRIBUTE),
			&objects,
			&objects_found
		);
	}

	for (i=0;rv == CKR_OK && i < objects_found;i++) {
		CK_ATTRIBUTE attrs[] = {
			{CKA_VALUE, NULL, 0}
		};

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_session_getObjectAttributes (
				certificate->session,
				objects[i],
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			)) == CKR_OK
		) {
			if (
				_pkcs11h_certificate_isBetterCertificate (
					certificate->id->certificate_blob,
					certificate->id->certificate_blob_size,
					attrs[0].pValue,
					attrs[0].ulValueLen
				)
			) {
				if (certificate->id->certificate_blob != NULL) {
					_pkcs11h_mem_free ((void *)&certificate->id->certificate_blob);
				}

				rv = _pkcs11h_mem_duplicate (
					(void*)&certificate->id->certificate_blob,
					&certificate->id->certificate_blob_size,
					attrs[0].pValue,
					attrs[0].ulValueLen
				);
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%lu-'%s'",
				certificate->session->provider->manufacturerID,
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
	
#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&certificate->session->mutex);
		mutex_locked = FALSE;
	}
#endif

	if (
		rv == CKR_OK &&
		certificate->id->certificate_blob == NULL
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
		"PKCS#11: __pkcs11h_certificate_loadCertificate return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
__pkcs11h_certificate_updateCertificateIdDescription (
	IN OUT pkcs11h_certificate_id_t certificate_id
) {
	static const char * separator = " on ";
	static const char * unknown = "UNKNOWN";

	PKCS11H_ASSERT (certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_certificate_updateCertificateIdDescription entry certificate_id=%p",
		(void *)certificate_id
	);

	if (
		certificate_id->certificate_blob_size != 0 &&
		!g_pkcs11h_crypto_engine.certificate_get_dn (
			g_pkcs11h_crypto_engine.global_data,
			certificate_id->certificate_blob,
			certificate_id->certificate_blob_size,
			certificate_id->displayName,
			sizeof (certificate_id->displayName)
		)
	) {
		certificate_id->displayName[0] = '\x0';
	}

	if (strlen (certificate_id->displayName) == 0) {
		strncpy (
			certificate_id->displayName,
			unknown,
			sizeof (certificate_id->displayName)-1
		);
	}

	/*
	 * Try to avoid using snprintf,
	 * may be unavailable
	 */
	strncat (
		certificate_id->displayName,
		separator,
		sizeof (certificate_id->displayName)-1-strlen (certificate_id->displayName)
	);
	strncat (
		certificate_id->displayName,
		certificate_id->token_id->display,
		sizeof (certificate_id->displayName)-1-strlen (certificate_id->displayName)
	);
	certificate_id->displayName[sizeof (certificate_id->displayName) - 1] = '\0';

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_certificate_updateCertificateIdDescription return displayName='%s'",
		certificate_id->displayName
	);

	return CKR_OK;
}

static
CK_RV
__pkcs11h_certificate_getKeyAttributes (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_RV rv = CKR_OK;

	PKCS11H_BOOL op_succeed = FALSE;
	PKCS11H_BOOL login_retry = FALSE;

	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_certificate_getKeyAttributes entry certificate=%p",
		(void *)certificate
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	certificate->mask_private_mode = 0;

	while (rv == CKR_OK && !op_succeed) {
		CK_ATTRIBUTE key_attrs[] = {
			{CKA_SIGN, NULL, 0},
			{CKA_SIGN_RECOVER, NULL, 0},
			{CKA_DECRYPT, NULL, 0},
			{CKA_UNWRAP, NULL, 0}
		};

		/*
		 * Don't try invalid object
		 */
		if (
			rv == CKR_OK &&
			certificate->key_handle == PKCS11H_INVALID_OBJECT_HANDLE
		) {
			rv = CKR_OBJECT_HANDLE_INVALID;
		}

		if (rv == CKR_OK) {
			if (certificate->session->provider->mask_private_mode != 0) {
				certificate->mask_private_mode = certificate->session->provider->mask_private_mode;
				op_succeed = TRUE;
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Key attributes enforced by provider (%08x)",
					certificate->mask_private_mode
				);
			}
		}

		if (rv == CKR_OK && !op_succeed) {
			rv = _pkcs11h_session_getObjectAttributes (
				certificate->session,
				certificate->key_handle,
				key_attrs,
				sizeof (key_attrs) / sizeof (CK_ATTRIBUTE)
			);
		}

		if (rv == CKR_OK && !op_succeed) {
			CK_BBOOL *key_attrs_sign = (CK_BBOOL *)key_attrs[0].pValue;
			CK_BBOOL *key_attrs_sign_recover = (CK_BBOOL *)key_attrs[1].pValue;
			CK_BBOOL *key_attrs_decrypt = (CK_BBOOL *)key_attrs[2].pValue;
			CK_BBOOL *key_attrs_unwrap = (CK_BBOOL *)key_attrs[3].pValue;

			if (key_attrs_sign != NULL && *key_attrs_sign != CK_FALSE) {
				certificate->mask_private_mode |= PKCS11H_PRIVATEMODE_MASK_SIGN;
			}
			if (key_attrs_sign_recover != NULL && *key_attrs_sign_recover != CK_FALSE) {
				certificate->mask_private_mode |= PKCS11H_PRIVATEMODE_MASK_RECOVER;
			}
			if (key_attrs_decrypt != NULL && *key_attrs_decrypt != CK_FALSE) {
				certificate->mask_private_mode |= PKCS11H_PRIVATEMODE_MASK_DECRYPT;
			}
			if (key_attrs_unwrap != NULL && *key_attrs_unwrap != CK_FALSE) {
				certificate->mask_private_mode |= PKCS11H_PRIVATEMODE_MASK_UNWRAP;
			}
			if (certificate->mask_private_mode == 0) {
				rv = CKR_KEY_TYPE_INCONSISTENT;
			}
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Key attributes loaded (%08x)",
				certificate->mask_private_mode
			);
		}

		_pkcs11h_session_freeObjectAttributes (
			key_attrs,
			sizeof (key_attrs) / sizeof (CK_ATTRIBUTE)
		);

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Get private key attributes failed: %ld:'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);

				rv = _pkcs11h_certificate_resetSession (
					certificate,
					FALSE,
					TRUE
				);

				login_retry = TRUE;
			}
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&certificate->mutex);
		mutex_locked = FALSE;
	}
#endif
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_certificate_getKeyAttributes return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
_pkcs11h_certificate_validateSession (
	IN const pkcs11h_certificate_t certificate
) {
	/*
	 * THREADING:
	 * certificate->mutex must be locked
	 * certificate->session->mutex must be locked
	 */
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_validateSession entry certificate=%p",
		(void *)certificate
	);

	if (certificate->session == NULL) {
		rv = CKR_SESSION_HANDLE_INVALID;
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_session_validate (certificate->session);
	}

	if (rv == CKR_OK) {
		if (certificate->key_handle == PKCS11H_INVALID_OBJECT_HANDLE) {
			rv = CKR_OBJECT_HANDLE_INVALID;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_validateSession return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
_pkcs11h_certificate_resetSession (
	IN const pkcs11h_certificate_t certificate,
	IN const PKCS11H_BOOL public_only,
	IN const PKCS11H_BOOL session_mutex_locked
) {
	/*
	 * THREADING:
	 * certificate->mutex must be locked
	 */
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	PKCS11H_BOOL is_key_valid = FALSE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (certificate!=NULL);
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_resetSession entry certificate=%p, public_only=%d, session_mutex_locked=%d",
		(void *)certificate,
		public_only ? 1 : 0,
		session_mutex_locked ? 1 : 0
	);

	if (rv == CKR_OK && certificate->session == NULL) {
		rv = _pkcs11h_session_getSessionByTokenId (certificate->id->token_id, &certificate->session);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		!session_mutex_locked &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		!certificate->pin_cache_populated_to_session
	) {
		certificate->pin_cache_populated_to_session = TRUE;

		if (certificate->pin_cache_period != PKCS11H_PIN_CACHE_INFINITE) {
			if (certificate->session->pin_cache_period != PKCS11H_PIN_CACHE_INFINITE) {
				if (certificate->session->pin_cache_period > certificate->pin_cache_period) {
					certificate->session->pin_expire_time = (
						certificate->session->pin_expire_time -
						(time_t)certificate->session->pin_cache_period +
						(time_t)certificate->pin_cache_period
					);
					certificate->session->pin_cache_period = certificate->pin_cache_period;
				}
			}
			else {
				certificate->session->pin_expire_time = (
					g_pkcs11h_sys_engine.time () +
					(time_t)certificate->pin_cache_period
				);
				certificate->session->pin_cache_period = certificate->pin_cache_period;
			}
		}	
	}

	/*
	 * First, if session seems to be valid
	 * and key handle is invalid (hard-set),
	 * try to fetch key handle,
	 * maybe the token is already logged in
	 */
	if (rv == CKR_OK) {
		if (
			certificate->session->session_handle != PKCS11H_INVALID_SESSION_HANDLE &&
			certificate->key_handle == PKCS11H_INVALID_OBJECT_HANDLE
		) {
			if (!public_only || certificate->session->provider->cert_is_private) {
				if (
					(rv = _pkcs11h_session_getObjectById (
						certificate->session,
						CKO_PRIVATE_KEY,
						certificate->id->attrCKA_ID,
						certificate->id->attrCKA_ID_size,
						&certificate->key_handle
					)) == CKR_OK
				) {
					is_key_valid = TRUE;
				}
				else {
					/*
					 * Ignore error
					 */
					rv = CKR_OK;
					certificate->key_handle = PKCS11H_INVALID_OBJECT_HANDLE;
				}
			}
		}
	}

	if (
		!is_key_valid &&
		rv == CKR_OK &&
		(rv = _pkcs11h_session_login (
			certificate->session,
			public_only,
			TRUE,
			certificate->user_data,
			certificate->mask_prompt
		)) == CKR_OK
	) {
		rv = __pkcs11h_certificate_updateCertificateIdDescription (certificate->id);
	}

	if (
		!is_key_valid &&
		rv == CKR_OK &&
		!public_only &&
		(rv = _pkcs11h_session_getObjectById (
			certificate->session,
			CKO_PRIVATE_KEY,
			certificate->id->attrCKA_ID,
			certificate->id->attrCKA_ID_size,
			&certificate->key_handle
		)) == CKR_OK
	) {
		is_key_valid = TRUE;
	}

	if (
		rv == CKR_OK &&
		!public_only &&
		!is_key_valid
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&certificate->session->mutex);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_resetSession return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
__pkcs11h_certificate_doPrivateOperation (
	IN const pkcs11h_certificate_t certificate,
	IN const enum _pkcs11h_private_op_e op,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_MECHANISM mech = {
		mech_type, NULL, 0
	};

/*	CK_BBOOL wrap_attrs_false = CK_FALSE; */
	CK_BBOOL wrap_attrs_true = CK_TRUE;
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_KEY_TYPE keytype = CKK_GENERIC_SECRET;
	CK_ATTRIBUTE wrap_attrs[] = {
		{CKA_CLASS, &class, sizeof (class)}, 
		{CKA_KEY_TYPE, &keytype, sizeof (keytype)},
		{CKA_EXTRACTABLE, &wrap_attrs_true, sizeof (wrap_attrs_true)}
/* OpenSC fail!	{CKA_TOKEN, &wrap_attrs_false, sizeof (wrap_attrs_false)} */
	};
	CK_ATTRIBUTE wrap_value[] = {
		{CKA_VALUE, target, 0}
	};
	CK_OBJECT_HANDLE wrap_key = PKCS11H_INVALID_OBJECT_HANDLE;
	
	CK_RV rv = CKR_OK;
	PKCS11H_BOOL login_retry = FALSE;
	PKCS11H_BOOL op_succeed = FALSE;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_certificate_doPrivateOperation entry certificate=%p, op=%d, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		op,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	while (rv == CKR_OK && !op_succeed) {
		if (rv == CKR_OK && !certificate->operation_active) {
			rv = _pkcs11h_certificate_validateSession (certificate);
		}

		if (rv == CKR_OK && !certificate->operation_active) {
			switch (op) {
				case _pkcs11h_private_op_sign:
					rv = certificate->session->provider->f->C_SignInit (
						certificate->session->session_handle,
						&mech,
						certificate->key_handle
					);
				break;
				case _pkcs11h_private_op_sign_recover:
					rv = certificate->session->provider->f->C_SignRecoverInit (
						certificate->session->session_handle,
						&mech,
						certificate->key_handle
					);
				break;
				case _pkcs11h_private_op_decrypt:
					rv = certificate->session->provider->f->C_DecryptInit (
						certificate->session->session_handle,
						&mech,
						certificate->key_handle
					);
				break;
				case _pkcs11h_private_op_unwrap:
					rv = certificate->session->provider->f->C_UnwrapKey (
						certificate->session->session_handle,
						&mech,
						certificate->key_handle,
						(CK_BYTE_PTR)source,
						source_size,
						wrap_attrs,
						sizeof (wrap_attrs) / sizeof (CK_ATTRIBUTE),
						&wrap_key
					);
				break;
				default:
					rv = CKR_ARGUMENTS_BAD;
				break;
			}

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG2,
				"PKCS#11: __pkcs11h_certificate_doPrivateOperation init rv=%ld",
				rv
			);
		}

		/*
		 * Assume one call operation
		 */
		certificate->operation_active = FALSE;

		if (rv == CKR_OK) {
			CK_ULONG size = *p_target_size;

			switch (op) {
				case _pkcs11h_private_op_sign:
					rv = certificate->session->provider->f->C_Sign (
						certificate->session->session_handle,
						(CK_BYTE_PTR)source,
						source_size,
						(CK_BYTE_PTR)target,
						&size
					);
				break;
				case _pkcs11h_private_op_sign_recover:
					rv = certificate->session->provider->f->C_SignRecover (
						certificate->session->session_handle,
						(CK_BYTE_PTR)source,
						source_size,
						(CK_BYTE_PTR)target,
						&size
					);
				break;
				case _pkcs11h_private_op_decrypt:
					rv = certificate->session->provider->f->C_Decrypt (
						certificate->session->session_handle,
						(CK_BYTE_PTR)source,
						source_size,
						(CK_BYTE_PTR)target,
						&size
					);
				break;
				case _pkcs11h_private_op_unwrap:
					wrap_value[0].ulValueLen = size;

					rv = certificate->session->provider->f->C_GetAttributeValue (
						certificate->session->session_handle,
						wrap_key,
						wrap_value,
						sizeof (wrap_value) / sizeof (CK_ATTRIBUTE)
					);

					size = wrap_value[0].ulValueLen;
				break;
				default:
					rv = CKR_ARGUMENTS_BAD;
				break;
			}

			*p_target_size = size;

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG2,
				"PKCS#11: __pkcs11h_certificate_doPrivateOperation op rv=%ld",
				rv
			);
		}
		
		if (wrap_key != PKCS11H_INVALID_OBJECT_HANDLE) {
			certificate->session->provider->f->C_DestroyObject (
				certificate->session->session_handle,
				wrap_key
			);
			wrap_key = PKCS11H_INVALID_OBJECT_HANDLE;
		}

		if (
			target == NULL &&
			(
				rv == CKR_BUFFER_TOO_SMALL ||
				rv == CKR_OK
			)
		) {
			if (op != _pkcs11h_private_op_unwrap) {
				certificate->operation_active = TRUE;
			}
			rv = CKR_OK;
		}

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			/*
			 * OpenSC workaround
			 * It still allows C_FindObjectsInit when
			 * token is removed/inserted but fails
			 * private key operation.
			 * So we force logout.
			 * bug#108 at OpenSC trac
			 */
			if (login_retry && rv == CKR_DEVICE_REMOVED) {
				login_retry = FALSE;
				_pkcs11h_session_logout (certificate->session);
			}

			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Private key operation failed rv=%lu-'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);
				login_retry = TRUE;
				rv = _pkcs11h_certificate_resetSession (
					certificate,
					FALSE,
					TRUE
				);
			}
		}

	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&certificate->mutex);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_certificate_doPrivateOperation return rv=%lu-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_freeCertificateId (
	IN pkcs11h_certificate_id_t certificate_id
) {
	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificateId entry certificate_id=%p",
		(void *)certificate_id
	);

	if (certificate_id->attrCKA_ID != NULL) {
		_pkcs11h_mem_free ((void *)&certificate_id->attrCKA_ID);
	}
	if (certificate_id->certificate_blob != NULL) {
		_pkcs11h_mem_free ((void *)&certificate_id->certificate_blob);
	}
	if (certificate_id->token_id != NULL) {
		pkcs11h_token_freeTokenId (certificate_id->token_id);
		certificate_id->token_id = NULL;
	}
	_pkcs11h_mem_free ((void *)&certificate_id);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificateId return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_certificate_duplicateCertificateId (
	OUT pkcs11h_certificate_id_t * const to,
	IN const pkcs11h_certificate_id_t from
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (to!=NULL);
	PKCS11H_ASSERT (from!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_duplicateCertificateId entry to=%p form=%p",
		(void *)to,
		(void *)from
	);

	*to = NULL;

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void*)to,
			NULL,
			from,
			sizeof (struct pkcs11h_certificate_id_s)
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void*)&(*to)->token_id,
			NULL,
			from->token_id,
			sizeof (struct pkcs11h_token_id_s)
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void*)&(*to)->attrCKA_ID,
			&(*to)->attrCKA_ID_size,
			from->attrCKA_ID,
			from->attrCKA_ID_size
		);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void*)&(*to)->certificate_blob,
			&(*to)->certificate_blob_size,
			from->certificate_blob,
			from->certificate_blob_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_duplicateCertificateId return rv=%lu-'%s', *to=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*to
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_setCertificateIdCertificateBlob (
	IN const pkcs11h_certificate_id_t certificate_id,
	IN const unsigned char * const blob,
	IN const size_t blob_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate_id!=NULL);
	PKCS11H_ASSERT (blob!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_setCertificateIdCertificateBlob entry certificate_id=%p",
		(void *)certificate_id
	);

	if (rv == CKR_OK && certificate_id->certificate_blob != NULL) {
		rv = _pkcs11h_mem_free ((void *)&certificate_id->certificate_blob);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_mem_duplicate (
			(void *)&certificate_id->certificate_blob,
			&certificate_id->certificate_blob_size,
			blob,
			blob_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_setCertificateIdCertificateBlob return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_freeCertificate (
	IN pkcs11h_certificate_t certificate
) {
	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificate entry certificate=%p",
		(void *)certificate
	);

	if (certificate != NULL) {
		if (certificate->session != NULL) {
			_pkcs11h_session_release (certificate->session);
		}
		pkcs11h_certificate_freeCertificateId (certificate->id);
		certificate->id = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_threading_mutexFree (&certificate->mutex);
#endif

		_pkcs11h_mem_free ((void *)&certificate);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificate return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_certificate_lockSession (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);

	if (rv == CKR_OK && certificate->session == NULL) {
		rv = _pkcs11h_session_getSessionByTokenId (certificate->id->token_id, &certificate->session);
	}

	if (rv == CKR_OK) {
		rv = _pkcs11h_threading_mutexLock (&certificate->session->mutex);
	}

	return rv;
#else
	return CKR_OK;
#endif
}

CK_RV
pkcs11h_certificate_releaseSession (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);

	if (certificate->session != NULL) {
		rv = _pkcs11h_threading_mutexRelease (&certificate->session->mutex);
	}

	return rv;
#else
	return CKR_OK;
#endif
}

CK_RV
pkcs11h_certificate_sign (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_sign entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	if (rv == CKR_OK) {
		rv = __pkcs11h_certificate_doPrivateOperation (
			certificate,
			_pkcs11h_private_op_sign,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_sign return rv=%lu-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_signRecover (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signRecover entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	if (rv == CKR_OK) {
		rv = __pkcs11h_certificate_doPrivateOperation (
			certificate,
			_pkcs11h_private_op_sign_recover,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signRecover return rv=%lu-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_decrypt (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_decrypt entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	if (rv == CKR_OK) {
		rv = __pkcs11h_certificate_doPrivateOperation (
			certificate,
			_pkcs11h_private_op_decrypt,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_decrypt return rv=%lu-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_unwrap (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_unwrap entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (target == NULL) {
		*p_target_size = 0;
	}

	if (rv == CKR_OK) {
		rv = __pkcs11h_certificate_doPrivateOperation (
			certificate,
			_pkcs11h_private_op_unwrap,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_unwrap return rv=%lu-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_signAny (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;
	PKCS11H_BOOL acked = FALSE;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signAny entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (
		rv == CKR_OK &&
		certificate->mask_private_mode == 0
	) {
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Getting key attributes"
		);
		rv = __pkcs11h_certificate_getKeyAttributes (certificate);
	}

	if (
		rv == CKR_OK &&
		!acked &&
		(certificate->mask_private_mode & PKCS11H_PRIVATEMODE_MASK_SIGN) != 0
	) {
		rv = pkcs11h_certificate_sign (
			certificate,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);

		if (rv == CKR_OK) {
			acked = TRUE;
		}
		else if (
			rv == CKR_FUNCTION_NOT_SUPPORTED ||
			rv == CKR_KEY_FUNCTION_NOT_PERMITTED ||
			rv == CKR_KEY_TYPE_INCONSISTENT
		) {
			certificate->mask_private_mode &= ~PKCS11H_PRIVATEMODE_MASK_SIGN;
			rv = CKR_OK;
		}
	}
	
	if (
		rv == CKR_OK &&
		!acked &&
		(certificate->mask_private_mode & PKCS11H_PRIVATEMODE_MASK_RECOVER) != 0
	) {
		rv = pkcs11h_certificate_signRecover (
			certificate,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);

		if (rv == CKR_OK) {
			acked = TRUE;
		}
		else if (
			rv == CKR_FUNCTION_NOT_SUPPORTED ||
			rv == CKR_KEY_FUNCTION_NOT_PERMITTED ||
			rv == CKR_KEY_TYPE_INCONSISTENT
		) {
			certificate->mask_private_mode &= ~PKCS11H_PRIVATEMODE_MASK_RECOVER;
			rv = CKR_OK;
		}
	}

	if (rv == CKR_OK && !acked) {
		rv = CKR_FUNCTION_FAILED;
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_signAny return rv=%lu-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_decryptAny (
	IN const pkcs11h_certificate_t certificate,
	IN const CK_MECHANISM_TYPE mech_type,
	IN const unsigned char * const source,
	IN const size_t source_size,
	OUT unsigned char * const target,
	IN OUT size_t * const p_target_size
) {
	CK_RV rv = CKR_OK;
	PKCS11H_BOOL acked = FALSE;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (source!=NULL);
	/*PKCS11H_ASSERT (target); NOT NEEDED*/
	PKCS11H_ASSERT (p_target_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_decryptAny entry certificate=%p, mech_type=%ld, source=%p, source_size=%u, target=%p, *p_target_size=%u",
		(void *)certificate,
		mech_type,
		source,
		source_size,
		target,
		target != NULL ? *p_target_size : 0
	);

	if (
		rv == CKR_OK &&
		certificate->mask_private_mode == 0
	) {
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG1,
			"PKCS#11: Getting key attributes"
		);
		rv = __pkcs11h_certificate_getKeyAttributes (certificate);
	}

	if (
		rv == CKR_OK &&
		!acked &&
		(certificate->mask_private_mode & PKCS11H_PRIVATEMODE_MASK_DECRYPT) != 0
	) {
		rv = pkcs11h_certificate_decrypt (
			certificate,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);

		if (rv == CKR_OK) {
			acked = TRUE;
		}
		else if (
			rv == CKR_FUNCTION_NOT_SUPPORTED ||
			rv == CKR_KEY_FUNCTION_NOT_PERMITTED ||
			rv == CKR_KEY_TYPE_INCONSISTENT
		) {
			certificate->mask_private_mode &= ~PKCS11H_PRIVATEMODE_MASK_DECRYPT;
			rv = CKR_OK;
		}
	}
	
	if (
		rv == CKR_OK &&
		!acked &&
		(certificate->mask_private_mode & PKCS11H_PRIVATEMODE_MASK_UNWRAP) != 0
	) {
		rv = pkcs11h_certificate_unwrap (
			certificate,
			mech_type,
			source,
			source_size,
			target,
			p_target_size
		);

		if (rv == CKR_OK) {
			acked = TRUE;
		}
		else if (
			rv == CKR_FUNCTION_NOT_SUPPORTED ||
			rv == CKR_KEY_FUNCTION_NOT_PERMITTED ||
			rv == CKR_KEY_TYPE_INCONSISTENT
		) {
			certificate->mask_private_mode &= ~PKCS11H_PRIVATEMODE_MASK_UNWRAP;
			rv = CKR_OK;
		}
	}

	if (rv == CKR_OK && !acked) {
		rv = CKR_FUNCTION_FAILED;
	}
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_decryptAny return rv=%lu-'%s', *p_target_size=%u",
		rv,
		pkcs11h_getMessage (rv),
		*p_target_size
	);

	return rv;
}

CK_RV
pkcs11h_certificate_create (
	IN const pkcs11h_certificate_id_t certificate_id,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	IN const int pin_cache_period,
	OUT pkcs11h_certificate_t * const p_certificate
) {
	pkcs11h_certificate_t certificate = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	/*PKCS11H_ASSERT (user_data!=NULL); NOT NEEDED */
	PKCS11H_ASSERT (p_certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_create entry certificate_id=%p, user_data=%p, mask_prompt=%08x, pin_cache_period=%d, p_certificate=%p",
		(void *)certificate_id,
		user_data,
		mask_prompt,
		pin_cache_period,
		(void *)p_certificate
	);

	*p_certificate = NULL;

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_mem_malloc ((void*)&certificate, sizeof (struct pkcs11h_certificate_s))) == CKR_OK
	) {
		certificate->user_data = user_data;
		certificate->mask_prompt = mask_prompt;
		certificate->key_handle = PKCS11H_INVALID_OBJECT_HANDLE;
		certificate->pin_cache_period = pin_cache_period;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (rv == CKR_OK) {
		rv = _pkcs11h_threading_mutexInit (&certificate->mutex);
	}
#endif

	if (rv == CKR_OK) {
		rv = pkcs11h_certificate_duplicateCertificateId (&certificate->id, certificate_id);
	}

	if (rv == CKR_OK) {
		*p_certificate = certificate;
		certificate = NULL;
	}

	if (certificate != NULL) {
#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_threading_mutexFree (&certificate->mutex);
#endif
		_pkcs11h_mem_free ((void *)&certificate);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_create return rv=%lu-'%s' *p_certificate=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)*p_certificate
	);
	
	return rv;
}

unsigned
pkcs11h_certificate_getPromptMask (
	IN const pkcs11h_certificate_t certificate
) {
	PKCS11H_ASSERT (certificate!=NULL);

	return certificate->mask_prompt;
}

void
pkcs11h_certificate_setPromptMask (
	IN const pkcs11h_certificate_t certificate,
	IN const unsigned mask_prompt
) {
	PKCS11H_ASSERT (certificate!=NULL);

	certificate->mask_prompt = mask_prompt;
}

void *
pkcs11h_certificate_getUserData (
	IN const pkcs11h_certificate_t certificate
) {
	PKCS11H_ASSERT (certificate!=NULL);

	return certificate->user_data;
}

void
pkcs11h_certificate_setUserData (
	IN const pkcs11h_certificate_t certificate,
	IN void * const user_data
) {
	PKCS11H_ASSERT (certificate!=NULL);

	certificate->user_data = user_data;
}

CK_RV
pkcs11h_certificate_getCertificateId (
	IN const pkcs11h_certificate_t certificate,
	OUT pkcs11h_certificate_id_t * const p_certificate_id
) {
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	PKCS11H_ASSERT (p_certificate_id!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateId entry certificate=%p, certificate_id=%p",
		(void *)certificate,
		(void *)p_certificate_id
	);

	if (rv == CKR_OK) {
		rv = pkcs11h_certificate_duplicateCertificateId (
			p_certificate_id,
			certificate->id
		);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateId return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_certificate_getCertificateBlob (
	IN const pkcs11h_certificate_t certificate,
	OUT unsigned char * const certificate_blob,
	IN OUT size_t * const p_certificate_blob_size
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	CK_RV rv = CKR_OK;
	size_t certifiate_blob_size_max = 0;
	
	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);
	/*PKCS11H_ASSERT (certificate_blob!=NULL); NOT NEEDED */
	PKCS11H_ASSERT (p_certificate_blob_size!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateBlob entry certificate=%p, certificate_blob=%p, *p_certificate_blob_size=%u",
		(void *)certificate,
		certificate_blob,
		certificate_blob != NULL ? *p_certificate_blob_size : 0
	);

	if (certificate_blob != NULL) {
		certifiate_blob_size_max = *p_certificate_blob_size;
	}
	*p_certificate_blob_size = 0;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (rv == CKR_OK && certificate->id->certificate_blob == NULL) {
		PKCS11H_BOOL op_succeed = FALSE;
		PKCS11H_BOOL login_retry = FALSE;
		while (rv == CKR_OK && !op_succeed) {
			if (certificate->session == NULL) {
				rv = CKR_SESSION_HANDLE_INVALID;
			}

			if (rv == CKR_OK) {
				rv = __pkcs11h_certificate_loadCertificate (certificate);
			}

			if (rv == CKR_OK) {
				op_succeed = TRUE;
			}
			else {
				if (!login_retry) {
					login_retry = TRUE;
					rv = _pkcs11h_certificate_resetSession (
						certificate,
						TRUE,
						FALSE
					);
				}
			}
		}
	}
	
	if (
		rv == CKR_OK &&
		certificate->id->certificate_blob == NULL
	) {
		rv = CKR_FUNCTION_REJECTED;
	}

	if (rv == CKR_OK) {
		__pkcs11h_certificate_updateCertificateIdDescription (certificate->id);
	}

	if (rv == CKR_OK) {
		*p_certificate_blob_size = certificate->id->certificate_blob_size;
	}

	if (certificate_blob != NULL) {
		if (
			rv == CKR_OK &&
			certificate->id->certificate_blob_size > certifiate_blob_size_max
		) {
			rv = CKR_BUFFER_TOO_SMALL;
		}
	
		if (rv == CKR_OK) {
			memmove (
				certificate_blob,
				certificate->id->certificate_blob,
				*p_certificate_blob_size
			);
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&certificate->mutex);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_getCertificateBlob return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_certificate_ensureCertificateAccess (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked_cert = FALSE;
	PKCS11H_BOOL mutex_locked_sess = FALSE;
#endif
	PKCS11H_BOOL validCert = FALSE;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureCertificateAccess entry certificate=%p",
		(void *)certificate
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->mutex)) == CKR_OK
	) {
		mutex_locked_cert = TRUE;
	}
#endif

	if (!validCert && rv == CKR_OK) {
		CK_OBJECT_HANDLE h = PKCS11H_INVALID_OBJECT_HANDLE;

		if (certificate->session == NULL) {
			rv = CKR_SESSION_HANDLE_INVALID;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_threading_mutexLock (&certificate->session->mutex)) == CKR_OK
		) {
			mutex_locked_sess = TRUE;
		}
#endif

		if (
			(rv = _pkcs11h_session_getObjectById (
				certificate->session,
				CKO_CERTIFICATE,
				certificate->id->attrCKA_ID,
				certificate->id->attrCKA_ID_size,
				&h
			)) == CKR_OK
		) {
			validCert = TRUE;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (mutex_locked_sess) {
			_pkcs11h_threading_mutexRelease (&certificate->session->mutex);
			mutex_locked_sess = FALSE;
		}
#endif

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot access existing object rv=%lu-'%s'",
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
		}
	}

	if (!validCert && rv == CKR_OK) {
		if (
			(rv = _pkcs11h_certificate_resetSession (
				certificate,
				TRUE,
				FALSE
			)) == CKR_OK
		) {
			validCert = TRUE;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked_cert) {
		_pkcs11h_threading_mutexRelease (&certificate->mutex);
		mutex_locked_cert = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureCertificateAccess return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_ensureKeyAccess (
	IN const pkcs11h_certificate_t certificate
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked_cert = FALSE;
	PKCS11H_BOOL mutex_locked_sess = FALSE;
#endif
	CK_RV rv = CKR_OK;
	PKCS11H_BOOL valid_key = FALSE;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (certificate!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureKeyAccess entry certificate=%p",
		(void *)certificate
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&certificate->mutex)) == CKR_OK
	) {
		mutex_locked_cert = TRUE;
	}
#endif

	if (!valid_key && rv == CKR_OK) {

		if (certificate->session == NULL) {
			rv = CKR_SESSION_HANDLE_INVALID;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_threading_mutexLock (&certificate->session->mutex)) == CKR_OK
		) {
			mutex_locked_sess = TRUE;
		}
#endif

		if (
			(rv = _pkcs11h_session_getObjectById (
				certificate->session,
				CKO_PRIVATE_KEY,
				certificate->id->attrCKA_ID,
				certificate->id->attrCKA_ID_size,
				&certificate->key_handle
			)) == CKR_OK
		) {
			valid_key = TRUE;
		}

#if defined(ENABLE_PKCS11H_THREADING)
		if (mutex_locked_sess) {
			_pkcs11h_threading_mutexRelease (&certificate->session->mutex);
			mutex_locked_sess = FALSE;
		}
#endif

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot access existing object rv=%lu-'%s'",
				rv,
				pkcs11h_getMessage (rv)
			);

			/*
			 * Ignore error
			 */
			rv = CKR_OK;
			certificate->key_handle = PKCS11H_INVALID_OBJECT_HANDLE;
		}
	}

	if (!valid_key && rv == CKR_OK) {
		if (
			(rv = _pkcs11h_certificate_resetSession (
				certificate,
				FALSE,
				FALSE
			)) == CKR_OK
		) {
			valid_key = TRUE;
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked_cert) {
		_pkcs11h_threading_mutexRelease (&certificate->mutex);
		mutex_locked_cert = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_ensureKeyAccess return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
_pkcs11h_certificate_enumSessionCertificates (
	IN const pkcs11h_session_t session,
	IN void * const user_data,
	IN const unsigned mask_prompt
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	PKCS11H_BOOL op_succeed = FALSE;
	PKCS11H_BOOL login_retry = FALSE;

	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (session!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_enumSessionCertificates entry session=%p, user_data=%p, mask_prompt=%08x",
		(void *)session,
		user_data,
		mask_prompt
	);
	
	/* THREADS: NO NEED TO LOCK, GLOBAL CACHE IS LOCKED */
#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&session->mutex)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	while (rv == CKR_OK && !op_succeed) {
		CK_OBJECT_CLASS cert_filter_class = CKO_CERTIFICATE;
		CK_ATTRIBUTE cert_filter[] = {
			{CKA_CLASS, &cert_filter_class, sizeof (cert_filter_class)}
		};

		CK_OBJECT_HANDLE *objects = NULL;
		CK_ULONG objects_found = 0;

		CK_ULONG i;

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
			pkcs11h_certificate_id_t certificate_id = NULL;
			pkcs11h_certificate_id_list_t new_element = NULL;
			
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
				(rv = _pkcs11h_certificate_newCertificateId (&certificate_id)) == CKR_OK
			) {
				rv = pkcs11h_token_duplicateTokenId (
					&certificate_id->token_id,
					session->token_id
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_mem_duplicate (
					(void*)&certificate_id->attrCKA_ID,
					&certificate_id->attrCKA_ID_size,
					attrs[0].pValue,
					attrs[0].ulValueLen
				);
			}

			if (rv == CKR_OK) {
				rv = _pkcs11h_mem_duplicate (
					(void*)&certificate_id->certificate_blob,
					&certificate_id->certificate_blob_size,
					attrs[1].pValue,
					attrs[1].ulValueLen
				);
			}

			if (rv == CKR_OK) {
				rv = __pkcs11h_certificate_updateCertificateIdDescription (certificate_id);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_mem_malloc (
					(void *)&new_element,
					sizeof (struct pkcs11h_certificate_id_list_s)
				)) == CKR_OK
			) {
				new_element->next = session->cached_certs;
				new_element->certificate_id = certificate_id;
				certificate_id = NULL;

				session->cached_certs = new_element;
				new_element = NULL;
			}

			if (certificate_id != NULL) {
				pkcs11h_certificate_freeCertificateId (certificate_id);
				certificate_id = NULL;
			}

			if (new_element != NULL) {
				_pkcs11h_mem_free ((void *)&new_element);
				new_element = NULL;
			}

			_pkcs11h_session_freeObjectAttributes (
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get object attribute for provider '%s' object %ld rv=%lu-'%s'",
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
		}

		if (objects != NULL) {
			_pkcs11h_mem_free ((void *)&objects);
		}

		if (rv == CKR_OK) {
			op_succeed = TRUE;
		}
		else {
			if (!login_retry) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Get certificate attributes failed: %ld:'%s'",
					rv,
					pkcs11h_getMessage (rv)
				);

				rv = _pkcs11h_session_login (
					session,
					TRUE,
					TRUE,
					user_data,
					(mask_prompt & PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT)
				);

				login_retry = TRUE;
			}
		}
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&session->mutex);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_certificate_enumSessionCertificates return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

static
CK_RV
__pkcs11h_certificate_splitCertificateIdList (
	IN const pkcs11h_certificate_id_list_t cert_id_all,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
) {
	typedef struct info_s {
		struct info_s *next;
		pkcs11h_certificate_id_t e;
		PKCS11H_BOOL is_issuer;
	} *info_t;

	pkcs11h_certificate_id_list_t cert_id_issuers_list = NULL;
	pkcs11h_certificate_id_list_t cert_id_end_list = NULL;

	info_t head = NULL;
	info_t info = NULL;

	CK_RV rv = CKR_OK;

	/*PKCS11H_ASSERT (cert_id_all!=NULL); NOT NEEDED */
	/*PKCS11H_ASSERT (p_cert_id_issuers_list!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_cert_id_end_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_certificate_splitCertificateIdList entry cert_id_all=%p, p_cert_id_issuers_list=%p, p_cert_id_end_list=%p",
		(void *)cert_id_all,
		(void *)p_cert_id_issuers_list,
		(void *)p_cert_id_end_list
	);

	if (p_cert_id_issuers_list != NULL) {
		*p_cert_id_issuers_list = NULL;
	}
	*p_cert_id_end_list = NULL;

	if (rv == CKR_OK) {
		pkcs11h_certificate_id_list_t entry = NULL;

		for (
			entry = cert_id_all;
			entry != NULL && rv == CKR_OK;
			entry = entry->next
		) {
			info_t new_info = NULL;

			if (rv == CKR_OK) {
				rv = _pkcs11h_mem_malloc ((void *)&new_info, sizeof (struct info_s));
			}

			if (rv == CKR_OK) {
				new_info->next = head;
				new_info->e = entry->certificate_id;
				head = new_info;
				new_info = NULL;
			}
		}

	}

	if (rv == CKR_OK) {
		for (
			info = head;
			info != NULL;
			info = info->next
		) {
			info_t info2 = NULL;

			for (
				info2 = head;
				info2 != NULL && !info->is_issuer;
				info2 = info2->next
			) {
				if (info != info2) {
					info->is_issuer = g_pkcs11h_crypto_engine.certificate_is_issuer (
						g_pkcs11h_crypto_engine.global_data,
						info->e->certificate_blob,
						info->e->certificate_blob_size,
						info2->e->certificate_blob,
						info2->e->certificate_blob_size
					);
				}

			}
		}
	}

	if (rv == CKR_OK) {
		for (
			info = head;
			info != NULL && rv == CKR_OK;
			info = info->next
		) {
			pkcs11h_certificate_id_list_t new_entry = NULL;

			if (rv == CKR_OK) {
				rv = _pkcs11h_mem_malloc (
					(void *)&new_entry,
					sizeof (struct pkcs11h_certificate_id_list_s)
				);
			}

			if (
				rv == CKR_OK &&
				(rv = pkcs11h_certificate_duplicateCertificateId (
					&new_entry->certificate_id,
					info->e
				)) == CKR_OK
			) {
				/*
				 * Should not free base list
				 */
				info->e = NULL;
			}

			if (rv == CKR_OK) {
				if (info->is_issuer) {
					new_entry->next = cert_id_issuers_list;
					cert_id_issuers_list = new_entry;
					new_entry = NULL;
				}
				else {
					new_entry->next = cert_id_end_list;
					cert_id_end_list = new_entry;
					new_entry = NULL;
				}
			}

			if (new_entry != NULL) {
				if (new_entry->certificate_id != NULL) {
					pkcs11h_certificate_freeCertificateId (new_entry->certificate_id);
				}
				_pkcs11h_mem_free ((void *)&new_entry);
			}
		}
	}

	if (rv == CKR_OK) {
		while (head != NULL) {
			info_t entry = head;
			head = head->next;

			_pkcs11h_mem_free ((void *)&entry);
		}
	}

	if (rv == CKR_OK && p_cert_id_issuers_list != NULL ) {
		*p_cert_id_issuers_list = cert_id_issuers_list;
		cert_id_issuers_list = NULL;
	}

	if (rv == CKR_OK) {
		*p_cert_id_end_list = cert_id_end_list;
		cert_id_end_list = NULL;
	}

	if (cert_id_issuers_list != NULL) {
		pkcs11h_certificate_freeCertificateIdList (cert_id_issuers_list);
	}

	if (cert_id_end_list != NULL) {
		pkcs11h_certificate_freeCertificateIdList (cert_id_end_list);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_certificate_splitCertificateIdList return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
pkcs11h_certificate_freeCertificateIdList (
	IN const pkcs11h_certificate_id_list_t cert_id_list
) {
	pkcs11h_certificate_id_list_t _id = cert_id_list;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	/*PKCS11H_ASSERT (cert_id_list!=NULL); NOT NEEDED*/

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificateIdList entry cert_id_list=%p",
		(void *)cert_id_list
	);

	while (_id != NULL) {
		pkcs11h_certificate_id_list_t x = _id;
		_id = _id->next;
		if (x->certificate_id != NULL) {
			pkcs11h_certificate_freeCertificateId (x->certificate_id);
		}
		x->next = NULL;
		_pkcs11h_mem_free ((void *)&x);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_freeCertificateIdList return"
	);

	return CKR_OK;
}

CK_RV
pkcs11h_certificate_enumTokenCertificateIds (
	IN const pkcs11h_token_id_t token_id,
	IN const unsigned method,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_session_t session = NULL;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	PKCS11H_ASSERT (token_id!=NULL);
	/*PKCS11H_ASSERT (user_data) NOT NEEDED */
	/*PKCS11H_ASSERT (p_cert_id_issuers_list!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_cert_id_end_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_enumTokenCertificateIds entry token_id=%p, method=%u, user_data=%p, mask_prompt=%08x, p_cert_id_issuers_list=%p, p_cert_id_end_list=%p",
		(void *)token_id,
		method,
		user_data,
		mask_prompt,
		(void *)p_cert_id_issuers_list,
		(void *)p_cert_id_end_list
	);

	if (p_cert_id_issuers_list != NULL) {
		*p_cert_id_issuers_list = NULL;
	}
	*p_cert_id_end_list = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&g_pkcs11h_data->mutexes.cache)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_session_getSessionByTokenId (
			token_id,
			&session
		)) == CKR_OK
	) {
		if (method == PKCS11H_ENUM_METHOD_RELOAD) {
			pkcs11h_certificate_freeCertificateIdList (session->cached_certs);
			session->cached_certs = NULL;
		}

		if (session->cached_certs == NULL) {
			rv = _pkcs11h_certificate_enumSessionCertificates (session, user_data, mask_prompt);
		}
	}

	if (rv == CKR_OK) {
		rv = __pkcs11h_certificate_splitCertificateIdList (
			session->cached_certs,
			p_cert_id_issuers_list,
			p_cert_id_end_list
		);
	}

	if (session != NULL) {
		_pkcs11h_session_release (session);
	}

#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&g_pkcs11h_data->mutexes.cache);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_enumTokenCertificateIds return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

CK_RV
pkcs11h_certificate_enumCertificateIds (
	IN const unsigned method,
	IN void * const user_data,
	IN const unsigned mask_prompt,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_issuers_list,
	OUT pkcs11h_certificate_id_list_t * const p_cert_id_end_list
) {
#if defined(ENABLE_PKCS11H_THREADING)
	PKCS11H_BOOL mutex_locked = FALSE;
#endif
	pkcs11h_certificate_id_list_t cert_id_list = NULL;
	pkcs11h_provider_t current_provider;
	pkcs11h_session_t current_session;
	CK_RV rv = CKR_OK;

	PKCS11H_ASSERT (g_pkcs11h_data!=NULL);
	PKCS11H_ASSERT (g_pkcs11h_data->initialized);
	/*PKCS11H_ASSERT (user_data!=NULL); NOT NEEDED*/
	/*PKCS11H_ASSERT (p_cert_id_issuers_list!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (p_cert_id_end_list!=NULL);

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_enumCertificateIds entry method=%u, mask_prompt=%08x, p_cert_id_issuers_list=%p, p_cert_id_end_list=%p",
		method,
		mask_prompt,
		(void *)p_cert_id_issuers_list,
		(void *)p_cert_id_end_list
	);

	if (p_cert_id_issuers_list != NULL) {
		*p_cert_id_issuers_list = NULL;
	}
	*p_cert_id_end_list = NULL;

#if defined(ENABLE_PKCS11H_THREADING)
	if (
		rv == CKR_OK &&
		(rv = _pkcs11h_threading_mutexLock (&g_pkcs11h_data->mutexes.cache)) == CKR_OK
	) {
		mutex_locked = TRUE;
	}
#endif

	for (
		current_session = g_pkcs11h_data->sessions;
		current_session != NULL;
		current_session = current_session->next
	) {
		current_session->touch = FALSE;
		if (method == PKCS11H_ENUM_METHOD_RELOAD) {
			pkcs11h_certificate_freeCertificateIdList (current_session->cached_certs);
			current_session->cached_certs = NULL;
		}
	}

	for (
		current_provider = g_pkcs11h_data->providers;
		(
			current_provider != NULL &&
			rv == CKR_OK
		);
		current_provider = current_provider->next
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
				rv == CKR_OK
			);
			slot_index++
		) {
			pkcs11h_session_t session = NULL;
			pkcs11h_token_id_t token_id = NULL;
			CK_TOKEN_INFO info;

			if (rv == CKR_OK) {
				rv = current_provider->f->C_GetTokenInfo (
					slots[slot_index],
					&info
				);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_token_getTokenId (
					&info,
					&token_id
				)) == CKR_OK &&
				(rv = _pkcs11h_session_getSessionByTokenId (
					token_id,
					&session
				)) == CKR_OK
			) {
				session->touch = TRUE;

				if (session->cached_certs == NULL) {
					rv = _pkcs11h_certificate_enumSessionCertificates (session, user_data, mask_prompt);
				}
			}

			if (rv != CKR_OK) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Cannot get token information for provider '%s' slot %ld rv=%lu-'%s'",
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

			if (session != NULL) {
				_pkcs11h_session_release (session);
				session = NULL;
			}

			if (token_id != NULL) {
				pkcs11h_token_freeTokenId (token_id);
				token_id = NULL;
			}
		}

		if (rv != CKR_OK) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Cannot get slot list for provider '%s' rv=%lu-'%s'",
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
	}

	for (
		current_session = g_pkcs11h_data->sessions;
		(
			current_session != NULL &&
			rv == CKR_OK
		);
		current_session = current_session->next
	) {
		if (
			method == PKCS11H_ENUM_METHOD_CACHE ||
			(
				(
					method == PKCS11H_ENUM_METHOD_RELOAD ||
					method == PKCS11H_ENUM_METHOD_CACHE_EXIST
				) &&
				current_session->touch
			)
		) {
			pkcs11h_certificate_id_list_t entry = NULL;

			for (
				entry = current_session->cached_certs;
				(
					entry != NULL &&
					rv == CKR_OK
				);
				entry = entry->next
			) {
				pkcs11h_certificate_id_list_t new_entry = NULL;

				if (
					rv == CKR_OK &&
					(rv = _pkcs11h_mem_malloc (
						(void *)&new_entry,
						sizeof (struct pkcs11h_certificate_id_list_s)
					)) == CKR_OK &&
					(rv = pkcs11h_certificate_duplicateCertificateId (
						&new_entry->certificate_id,
						entry->certificate_id
					)) == CKR_OK
				) {
					new_entry->next = cert_id_list;
					cert_id_list = new_entry;
					new_entry = NULL;
				}

				if (new_entry != NULL) {
					new_entry->next = NULL;
					pkcs11h_certificate_freeCertificateIdList (new_entry);
					new_entry = NULL;
				}
			}
		}
	}

	if (rv == CKR_OK) {
		rv = __pkcs11h_certificate_splitCertificateIdList (
			cert_id_list,
			p_cert_id_issuers_list,
			p_cert_id_end_list
		);
	}

	if (cert_id_list != NULL) {
		pkcs11h_certificate_freeCertificateIdList (cert_id_list);
		cert_id_list = NULL;
	}


#if defined(ENABLE_PKCS11H_THREADING)
	if (mutex_locked) {
		_pkcs11h_threading_mutexRelease (&g_pkcs11h_data->mutexes.cache);
		mutex_locked = FALSE;
	}
#endif

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_enumCertificateIds return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);
	
	return rv;
}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */
