/*
 * Copyright (c) 2005-2011 Alon Bar-Lev <alon.barlev@gmail.com>
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
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
 *     o Neither the name of the Alon Bar-Lev nor the names of its
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

#include "_pkcs11h-core.h"
#include "_pkcs11h-mem.h"
#include "_pkcs11h-util.h"
#include "_pkcs11h-token.h"
#include "_pkcs11h-certificate.h"

#include <p11-kit/uri.h>

#define __PKCS11H_SERIALIZE_INVALID_CHARS	"\\/\"'%&#@!?$* <>{}[]()`|:;,.+-"

#if defined(ENABLE_PKCS11H_TOKEN) || defined(ENABLE_PKCS11H_CERTIFICATE)

static void set_tokinfo_string(char *dest, char *src, size_t dst_size)
{
	int i;

	strncpy(dest, src, dst_size);

	for (i = strlen(src); i < dst_size; i++)
		dest[i] = ' ';
}

CK_RV
pkcs11h_token_serializeTokenId (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_token_id_t token_id
) {
	P11KitUri *uri = NULL;
	CK_TOKEN_INFO *tokinfo;
	CK_RV rv = CKR_FUNCTION_FAILED;
	char *uristr = NULL;

	/*_PKCS11H_ASSERT (sz!=NULL); Not required*/
	_PKCS11H_ASSERT (max!=NULL);
	_PKCS11H_ASSERT (token_id!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_serializeTokenId entry sz=%p, *max="P_Z", token_id=%p",
		sz,
		sz != NULL ? *max : 0,
		(void *)token_id
	);

	uri = p11_kit_uri_new ();
	if (!uri)
		goto cleanup;

	tokinfo = p11_kit_uri_get_token_info (uri);

	set_tokinfo_string (tokinfo->manufacturerID, token_id->manufacturerID,
			    sizeof(tokinfo->manufacturerID));
	set_tokinfo_string (tokinfo->model, token_id->model,
			    sizeof(tokinfo->model));
	set_tokinfo_string (tokinfo->serialNumber, token_id->serialNumber,
			    sizeof(tokinfo->serialNumber));
	set_tokinfo_string (tokinfo->label, token_id->label,
			   sizeof(tokinfo->label));

	if (p11_kit_uri_format (uri, P11_KIT_URI_FOR_TOKEN, &uristr)
	    != P11_KIT_URI_OK)
		goto cleanup;

	if (strlen (uristr) < *max) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto cleanup;
	}

	if (sz) {
		if (strlen (uristr) < *max) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto cleanup;
		}
		strcpy (sz, uristr);
	}
	rv = CKR_OK;
	rv = CKR_OK;

cleanup:

	if (uri) {
		p11_kit_uri_free (uri);
		uri = NULL;
	}
	if (uristr) {
		*max = strlen (uristr);
		free (uristr);
		uristr = NULL;
	}
	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_serializeTokenId return rv=%lu-'%s', *max="P_Z", sz='%s'",
		rv,
		pkcs11h_getMessage (rv),
		*max,
		sz
	);

	return rv;
}

static CK_RV
pkcs11h_token_legacy_deserializeTokenId (
	OUT pkcs11h_token_id_t *p_token_id,
	IN const char * const sz
) {
#define __PKCS11H_TARGETS_NUMBER 4
	struct {
		char *p;
		size_t s;
	} targets[__PKCS11H_TARGETS_NUMBER];

	pkcs11h_token_id_t token_id = NULL;
	char *p1 = NULL;
	char *_sz = NULL;
	int e;
	CK_RV rv = CKR_FUNCTION_FAILED;

	if (
		(rv = _pkcs11h_mem_strdup (
			(void *)&_sz,
			sz
		)) != CKR_OK
	) {
		goto cleanup;
	}

	p1 = _sz;

	if ((rv = _pkcs11h_token_newTokenId (&token_id)) != CKR_OK) {
		goto cleanup;
	}

	targets[0].p = token_id->manufacturerID;
	targets[0].s = sizeof (token_id->manufacturerID);
	targets[1].p = token_id->model;
	targets[1].s = sizeof (token_id->model);
	targets[2].p = token_id->serialNumber;
	targets[2].s = sizeof (token_id->serialNumber);
	targets[3].p = token_id->label;
	targets[3].s = sizeof (token_id->label);

	for (e=0;e < __PKCS11H_TARGETS_NUMBER;e++) {
		size_t l;
		char *p2 = NULL;

		/*
		 * Don't search for last
		 * separator
		 */
		if (e != __PKCS11H_TARGETS_NUMBER-1) {
			p2 = strchr (p1, '/');
			if (p2 == NULL) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
				goto cleanup;
			}
			else {
				*p2 = '\x0';
			}
		}

		if (
			(rv = _pkcs11h_util_unescapeString (
				NULL,
				p1,
				&l
			)) != CKR_OK
		) {
			goto cleanup;
		}

		if (l > targets[e].s) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto cleanup;
		}

		l = targets[e].s;

		if (
			(rv = _pkcs11h_util_unescapeString (
				targets[e].p,
				p1,
				&l
			)) != CKR_OK
		) {
			goto cleanup;
		}

		p1 = p2+1;
	}

	strncpy (
		token_id->display,
		token_id->label,
		sizeof (token_id->display)
	);

	*p_token_id = token_id;
	token_id = NULL;

	rv = CKR_OK;

cleanup:

	if (_sz != NULL) {
		_pkcs11h_mem_free ((void *)&_sz);
	}

	if (token_id != NULL) {
		pkcs11h_token_freeTokenId (token_id);
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_deserializeTokenId return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
#undef __PKCS11H_TARGETS_NUMBER
}
CK_RV
pkcs11h_token_deserializeTokenId (
	OUT pkcs11h_token_id_t *p_token_id,
	IN const char * const sz
) {
#define __PKCS11H_TARGETS_NUMBER 4
	struct {
		char *p;
		size_t s;
	} targets[__PKCS11H_TARGETS_NUMBER];

	pkcs11h_token_id_t token_id = NULL;
	P11KitUri *uri = NULL;
	char *_sz = NULL;
	int e;
	CK_RV rv = CKR_FUNCTION_FAILED;
	CK_TOKEN_INFO *tokinfo;

	_PKCS11H_ASSERT (p_token_id!=NULL);
	_PKCS11H_ASSERT (sz!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_deserializeTokenId entry p_token_id=%p, sz='%s'",
		(void *)p_token_id,
		sz
	);

	*p_token_id = NULL;

	if (strncmp (sz, "pkcs11:", 7))
		return pkcs11h_token_legacy_deserializeTokenId(p_token_id, sz);

	uri = p11_kit_uri_new ();
	if (!uri)
		goto cleanup;

	if (p11_kit_uri_parse (sz, P11_KIT_URI_FOR_TOKEN, uri) !=
	    P11_KIT_URI_OK) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto cleanup;
	}

	tokinfo = p11_kit_uri_get_token_info (uri);

	if ((rv = _pkcs11h_token_newTokenId (&token_id)) != CKR_OK) {
		goto cleanup;
	}

	_pkcs11h_util_fixupFixedString (
		token_id->manufacturerID,
		(char *)tokinfo->manufacturerID,
		sizeof (tokinfo->manufacturerID)
	);
	_pkcs11h_util_fixupFixedString (
		token_id->model,
		(char *)tokinfo->model,
		sizeof (tokinfo->model)
	);
	_pkcs11h_util_fixupFixedString (
		token_id->serialNumber,
		(char *)tokinfo->serialNumber,
		sizeof (tokinfo->serialNumber)
	);
	_pkcs11h_util_fixupFixedString (
		token_id->label,
		(char *)tokinfo->label,
		sizeof (tokinfo->label)
	);

	strncpy (
		token_id->display,
		token_id->label,
		sizeof (token_id->display)
	);

	*p_token_id = token_id;
	token_id = NULL;

	rv = CKR_OK;

cleanup:
	if (uri != NULL) {
		p11_kit_uri_free (uri);
	}
	if (_sz != NULL) {
		_pkcs11h_mem_free ((void *)&_sz);
	}

	if (token_id != NULL) {
		pkcs11h_token_freeTokenId (token_id);
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_deserializeTokenId return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
#undef __PKCS11H_TARGETS_NUMBER
}

#endif				/* ENABLE_PKCS11H_TOKEN || ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

CK_RV
pkcs11h_certificate_serializeCertificateId (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_certificate_id_t certificate_id
) {
	P11KitUri *uri = NULL;
	CK_TOKEN_INFO *tokinfo;
	CK_RV rv = CKR_FUNCTION_FAILED;
	CK_ATTRIBUTE id_attr;
	char *uristr = NULL;

	/*_PKCS11H_ASSERT (sz!=NULL); Not required */
	_PKCS11H_ASSERT (max!=NULL);
	_PKCS11H_ASSERT (certificate_id!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_serializeCertificateId entry sz=%p, *max="P_Z", certificate_id=%p",
		sz,
		sz != NULL ? *max : 0,
		(void *)certificate_id
	);

	uri = p11_kit_uri_new ();
	if (!uri)
		goto cleanup;

	tokinfo = p11_kit_uri_get_token_info (uri);

	set_tokinfo_string (tokinfo->manufacturerID, certificate_id->token_id->manufacturerID,
			    sizeof(tokinfo->manufacturerID));
	set_tokinfo_string (tokinfo->model, certificate_id->token_id->model,
			    sizeof(tokinfo->model));
	set_tokinfo_string (tokinfo->serialNumber, certificate_id->token_id->serialNumber,
			    sizeof(tokinfo->serialNumber));
	set_tokinfo_string (tokinfo->label, certificate_id->token_id->label,
			   sizeof(tokinfo->label));

	id_attr.pValue = certificate_id->attrCKA_ID;
	id_attr.ulValueLen = certificate_id->attrCKA_ID_size;
	id_attr.type = CKA_ID;

	p11_kit_uri_set_attribute (uri, &id_attr);

	if (p11_kit_uri_format (uri, P11_KIT_URI_FOR_ANY, &uristr)
	    != P11_KIT_URI_OK)
		goto cleanup;

	if (sz) {
		if (strlen (uristr) < *max) {
			rv = CKR_ATTRIBUTE_VALUE_INVALID;
			goto cleanup;
		}
		strcpy (sz, uristr);
	}
	rv = CKR_OK;

cleanup:
	if (uri) {
		p11_kit_uri_free (uri);
		uri = NULL;
	}
	if (uristr) {
		*max = strlen (uristr);
		free (uristr);
		uristr = NULL;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_serializeCertificateId return rv=%lu-'%s', *max="P_Z", sz='%s'",
		rv,
		pkcs11h_getMessage (rv),
		*max,
		sz
	);

	return rv;
}

static CK_RV
pkcs11h_certificate_legacy_deserializeCertificateId (
	OUT pkcs11h_certificate_id_t * const p_certificate_id,
	IN const char * const sz
) {
	pkcs11h_certificate_id_t certificate_id = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;
	char *p = NULL;
	char *_sz = NULL;

	if (
		(rv = _pkcs11h_mem_strdup (
			(void *)&_sz,
			sz
		)) != CKR_OK
	) {
		goto cleanup;
	}

	p = _sz;

	if ((rv = _pkcs11h_certificate_newCertificateId (&certificate_id)) != CKR_OK) {
		goto cleanup;
	}

	if ((p = strrchr (_sz, '/')) == NULL) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto cleanup;
	}

	*p = '\x0';
	p++;

	if (
		(rv = pkcs11h_token_deserializeTokenId (
			&certificate_id->token_id,
			_sz
		)) != CKR_OK
	) {
		goto cleanup;
	}

	certificate_id->attrCKA_ID_size = strlen (p)/2;

	if (
		(rv = _pkcs11h_mem_malloc (
			(void *)&certificate_id->attrCKA_ID,
			certificate_id->attrCKA_ID_size)
		) != CKR_OK ||
		(rv = _pkcs11h_util_hexToBinary (
			certificate_id->attrCKA_ID,
			p,
			&certificate_id->attrCKA_ID_size
		)) != CKR_OK
	) {
		goto cleanup;
	}

	*p_certificate_id = certificate_id;
	certificate_id = NULL;
	rv = CKR_OK;

cleanup:

	if (certificate_id != NULL) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}

	if (_sz != NULL) {
		_pkcs11h_mem_free ((void *)&_sz);
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_legacy_deserializeCertificateId return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;

}

CK_RV
pkcs11h_certificate_deserializeCertificateId (
	OUT pkcs11h_certificate_id_t * const p_certificate_id,
	IN const char * const sz
) {
	pkcs11h_certificate_id_t certificate_id = NULL;
	pkcs11h_token_id_t token_id = NULL;
	P11KitUri *uri = NULL;
	CK_TOKEN_INFO *tokinfo;
	CK_ATTRIBUTE *attr;
	CK_RV rv = CKR_FUNCTION_FAILED;
	char *p = NULL;
	char *_sz = NULL;

	_PKCS11H_ASSERT (p_certificate_id!=NULL);
	_PKCS11H_ASSERT (sz!=NULL);

	*p_certificate_id = NULL;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_deserializeCertificateId entry p_certificate_id=%p, sz='%s'",
		(void *)p_certificate_id,
		sz
	);

	if (strncmp(sz, "pkcs11:", 7))
		return pkcs11h_certificate_legacy_deserializeCertificateId (p_certificate_id, sz);

	uri = p11_kit_uri_new ();
	if (!uri)
		goto cleanup;

	if (p11_kit_uri_parse (sz, P11_KIT_URI_FOR_ANY, uri) !=
	    P11_KIT_URI_OK) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto cleanup;
	}

	tokinfo = p11_kit_uri_get_token_info(uri);

	if ((rv = _pkcs11h_certificate_newCertificateId (&certificate_id)) != CKR_OK) {
		goto cleanup;
	}
	if ((rv = _pkcs11h_token_newTokenId (&token_id)) != CKR_OK) {
		goto cleanup;
	}

	certificate_id->token_id = token_id;

	_pkcs11h_util_fixupFixedString (
		token_id->manufacturerID,
		(char *)tokinfo->manufacturerID,
		sizeof (tokinfo->manufacturerID)
	);
	_pkcs11h_util_fixupFixedString (
		token_id->model,
		(char *)tokinfo->model,
		sizeof (tokinfo->model)
	);
	_pkcs11h_util_fixupFixedString (
		token_id->serialNumber,
		(char *)tokinfo->serialNumber,
		sizeof (tokinfo->serialNumber)
	);
	_pkcs11h_util_fixupFixedString (
		token_id->label,
		(char *)tokinfo->label,
		sizeof (tokinfo->label)
	);
	strncpy (
		token_id->display,
		token_id->label,
		sizeof (token_id->display)
	);

	attr = p11_kit_uri_get_attribute (uri, CKA_ID);
	if (!attr) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto cleanup;
	}

	certificate_id->attrCKA_ID_size = attr->ulValueLen;

	if (
		(rv = _pkcs11h_mem_malloc (
			(void *)&certificate_id->attrCKA_ID,
			certificate_id->attrCKA_ID_size)
		) != CKR_OK
	) {
		goto cleanup;
	}

	memcpy(certificate_id->attrCKA_ID, attr->pValue, attr->ulValueLen);

	*p_certificate_id = certificate_id;
	certificate_id = NULL;
	token_id = NULL;
	rv = CKR_OK;

cleanup:
	if (uri != NULL) {
		p11_kit_uri_free(uri);
	}

	if (certificate_id != NULL) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}
	if (token_id != NULL) {
		pkcs11h_token_freeTokenId (token_id);
		token_id = NULL;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_deserializeCertificateId return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;

}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

