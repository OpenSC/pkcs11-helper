/*
 * Copyright (c) 2005-2018 Alon Bar-Lev <alon.barlev@gmail.com>
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

#define __PKCS11H_SERIALIZE_INVALID_CHARS	"\\/\"'%&#@!?$* <>{}[]()`|:;,.+-"

#if defined(ENABLE_PKCS11H_TOKEN) || defined(ENABLE_PKCS11H_CERTIFICATE)

#define URI_SCHEME "pkcs11:"

#define token_field_ofs(field) ((unsigned long)&(((struct pkcs11h_token_id_s *)0)->field))
#define token_field_size(field) sizeof((((struct pkcs11h_token_id_s *)0)->field))
#define token_field(name, field) { name "=", sizeof(name), \
				   token_field_ofs(field), token_field_size(field) }

static struct {
	const char const *name;
	size_t namelen;
	unsigned long field_ofs;
	size_t field_size;
} __token_fields[] = {
	token_field ("model", model),
	token_field ("token", label),
	token_field ("manufacturer", manufacturerID ),
	token_field ("serial", serialNumber ),
	{ NULL },
};

#define               P11_URL_VERBATIM      "abcdefghijklmnopqrstuvwxyz" \
                                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                                            "0123456789_-."

static
int
__token_attr_escape(char *uri, char *attr, size_t attrlen)
{
	int len = 0, i;

	for (i = 0; i < attrlen; i++) {
		if ((attr[i] != '\x0') && strchr(P11_URL_VERBATIM, attr[i])) {
			if (uri) {
				*(uri++) = attr[i];
			}
			len++;
		} else {
			if (uri) {
				sprintf(uri, "%%%02x", (unsigned char)attr[i]);
				uri += 3;
			}
			len += 3;
		}
	}
	return len;
}

static
CK_RV
__generate_pkcs11_uri (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_certificate_id_t certificate_id,
	IN const pkcs11h_token_id_t token_id
) {
	size_t _max;
	char *p = sz;
	int i;

	_PKCS11H_ASSERT (max!=NULL);
	_PKCS11H_ASSERT (token_id!=NULL);

	_max = strlen(URI_SCHEME);
	for (i = 0; __token_fields[i].name; i++) {
		char *field = ((char *)token_id) + __token_fields[i].field_ofs;

		_max += __token_fields[i].namelen;
		_max += __token_attr_escape (NULL, field, strlen(field));
		_max++; /* For a semicolon or trailing NUL */
	}
	if (certificate_id) {
		_max += strlen (";id=");
		_max += __token_attr_escape (NULL,
					     (char *)certificate_id->attrCKA_ID,
					     certificate_id->attrCKA_ID_size);
	}

	if (!sz) {
		*max = _max;
		return CKR_OK;
	}

	if (sz && *max < _max)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	p += sprintf(p, URI_SCHEME);
	for (i = 0; __token_fields[i].name; i++) {
		char *field = ((char *)token_id) + __token_fields[i].field_ofs;

		p += sprintf (p, "%s", __token_fields[i].name);
		p += __token_attr_escape (p, field, strlen(field));
		*(p++) = ';';
	}
	if (certificate_id) {
		p += sprintf (p, "id=");
		p += __token_attr_escape (p,
					  (char *)certificate_id->attrCKA_ID,
					  certificate_id->attrCKA_ID_size);
	} else {
		/* Remove the unneeded trailing semicolon */
		p--;
	}
	*(p++) = 0;

	*max = _max;

	return CKR_OK;
}

CK_RV
pkcs11h_token_serializeTokenId (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_token_id_t token_id
) {
	CK_RV rv = CKR_FUNCTION_FAILED;

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

	rv = __generate_pkcs11_uri(sz, max, NULL, token_id);

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

static
CK_RV
__parse_token_uri_attr (
	const char *uri,
	size_t urilen,
	char *tokstr,
	size_t toklen,
	size_t *parsed_len
) {
	size_t orig_toklen = toklen;
	CK_RV rv = CKR_OK;

	while (urilen && toklen > 1) {
		if (*uri == '%') {
			size_t size = 1;

			if (urilen < 3) {
				rv = CKR_ATTRIBUTE_VALUE_INVALID;
				goto done;
			}

			rv = _pkcs11h_util_hexToBinary ((unsigned char *)tokstr,
							uri + 1, &size);
			if (rv != CKR_OK) {
				goto done;
			}

			uri += 2;
			urilen -= 2;
		} else {
			*tokstr = *uri;
		}
		tokstr++;
		uri++;
		toklen--;
		urilen--;
		tokstr[0] = 0;
	}

	if (urilen) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
	} else if (parsed_len) {
		*parsed_len = orig_toklen - toklen;
	}

 done:
	return rv;
}

static
CK_RV
__parse_pkcs11_uri (
	OUT pkcs11h_token_id_t token_id,
	OUT pkcs11h_certificate_id_t certificate_id,
	IN const char * const sz
) {
	const char *end, *p;
	CK_RV rv = CKR_OK;

	_PKCS11H_ASSERT (token_id!=NULL);
	_PKCS11H_ASSERT (sz!=NULL);

	if (strncmp (sz, URI_SCHEME, strlen (URI_SCHEME)))
		return CKR_ATTRIBUTE_VALUE_INVALID;

	end = sz + strlen (URI_SCHEME) - 1;
	while (rv == CKR_OK && end[0] && end[1]) {
		int i;

		p = end + 1;
	        end = strchr (p, ';');
		if (!end)
			end = p + strlen(p);

		for (i = 0; __token_fields[i].name; i++) {
			/* Parse the token=, label=, manufacturer= and serial= fields */
			if (!strncmp(p, __token_fields[i].name, __token_fields[i].namelen)) {
				char *field = ((char *)token_id) + __token_fields[i].field_ofs;

				p += __token_fields[i].namelen;
				rv = __parse_token_uri_attr (p, end - p, field,
							     __token_fields[i].field_size,
							     NULL);
				if (rv != CKR_OK) {
					goto cleanup;
				}

				goto matched;
			}
		}
		if (certificate_id && !strncmp(p, "id=", 3)) {
			p += 3;

			rv = _pkcs11h_mem_malloc ((void *)&certificate_id->attrCKA_ID,
						  end - p + 1);
			if (rv != CKR_OK) {
				goto cleanup;
			}

			rv = __parse_token_uri_attr (p, end - p,
						     (char *)certificate_id->attrCKA_ID,
						     end - p + 1,
						     &certificate_id->attrCKA_ID_size);
			if (rv != CKR_OK) {
				goto cleanup;
			}

			goto matched;
		}

		/* We don't parse object= because the match code doesn't support
		   matching by label. */

		/* Failed to parse PKCS#11 URI element. */
		return CKR_ATTRIBUTE_VALUE_INVALID;

		matched:
		    ;
	}
cleanup:
	/* The matching code doesn't support support partial matches; it needs
	 * *all* of manufacturer, model, serial and label attributes to be
	 * defined. So reject partial URIs early instead of letting it do the
	 * wrong thing. We can maybe improve this later. */
	if (!token_id->model[0] || !token_id->label[0] ||
	    !token_id->manufacturerID[0] || !token_id->serialNumber[0]) {
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	/* For a certificate ID we need CKA_ID */
	if (certificate_id && !certificate_id->attrCKA_ID_size) {
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	return rv;
}

static
CK_RV
__pkcs11h_token_legacy_deserializeTokenId (
	OUT pkcs11h_token_id_t token_id,
	IN const char * const sz
) {
#define __PKCS11H_TARGETS_NUMBER 4
	struct {
		char *p;
		size_t s;
	} targets[__PKCS11H_TARGETS_NUMBER];

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

	rv = CKR_OK;

cleanup:

	if (_sz != NULL) {
		_pkcs11h_mem_free ((void *)&_sz);
	}

	return rv;
#undef __PKCS11H_TARGETS_NUMBER
}

CK_RV
pkcs11h_token_deserializeTokenId (
	OUT pkcs11h_token_id_t *p_token_id,
	IN const char * const sz
) {
	pkcs11h_token_id_t token_id = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;

	_PKCS11H_ASSERT (p_token_id!=NULL);
	_PKCS11H_ASSERT (sz!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_token_deserializeTokenId entry p_token_id=%p, sz='%s'",
		(void *)p_token_id,
		sz
	);

	*p_token_id = NULL;

	if ((rv = _pkcs11h_token_newTokenId (&token_id)) != CKR_OK) {
		goto cleanup;
	}

	if (!strncmp (sz, URI_SCHEME, strlen (URI_SCHEME))) {
		rv = __parse_pkcs11_uri(token_id, NULL, sz);
	} else {
		rv = __pkcs11h_token_legacy_deserializeTokenId(token_id, sz);
	}
	if (rv != CKR_OK) {
		goto cleanup;
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
}

#endif				/* ENABLE_PKCS11H_TOKEN || ENABLE_PKCS11H_CERTIFICATE */

#if defined(ENABLE_PKCS11H_CERTIFICATE)

CK_RV
pkcs11h_certificate_serializeCertificateId (
	OUT char * const sz,
	IN OUT size_t *max,
	IN const pkcs11h_certificate_id_t certificate_id
) {
	CK_RV rv = CKR_FUNCTION_FAILED;

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

	rv = __generate_pkcs11_uri(sz, max, certificate_id, certificate_id->token_id);

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

static
CK_RV
__pkcs11h_certificate_legacy_deserializeCertificateId (
	OUT pkcs11h_certificate_id_t certificate_id,
	IN const char * const sz
) {
	CK_RV rv = CKR_FUNCTION_FAILED;
	char *p = NULL;
	char *_sz = NULL;
	size_t id_hex_len;

	if (
		(rv = _pkcs11h_mem_strdup (
			(void *)&_sz,
			sz
		)) != CKR_OK
	) {
		goto cleanup;
	}

	p = _sz;

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

	id_hex_len = strlen (p);
	if (id_hex_len & 1) {
		rv = CKR_ATTRIBUTE_VALUE_INVALID;
		goto cleanup;
	}
	certificate_id->attrCKA_ID_size = id_hex_len/2;

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

	rv = CKR_OK;

cleanup:

	if (_sz != NULL) {
		_pkcs11h_mem_free ((void *)&_sz);
	}

	return rv;

}

CK_RV
pkcs11h_certificate_deserializeCertificateId (
	OUT pkcs11h_certificate_id_t * const p_certificate_id,
	IN const char * const sz
) {
	pkcs11h_certificate_id_t certificate_id = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;

	_PKCS11H_ASSERT (p_certificate_id!=NULL);
	_PKCS11H_ASSERT (sz!=NULL);

	*p_certificate_id = NULL;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_deserializeCertificateId entry p_certificate_id=%p, sz='%s'",
		(void *)p_certificate_id,
		sz
	);

	if ((rv = _pkcs11h_certificate_newCertificateId (&certificate_id)) != CKR_OK) {
		goto cleanup;
	}
	if ((rv = _pkcs11h_token_newTokenId (&certificate_id->token_id)) != CKR_OK) {
		goto cleanup;
	}

	if (!strncmp(sz, URI_SCHEME, strlen (URI_SCHEME))) {
		rv = __parse_pkcs11_uri (certificate_id->token_id, certificate_id, sz);
	} else {
		rv = __pkcs11h_certificate_legacy_deserializeCertificateId (certificate_id, sz);
	}
	if (rv != CKR_OK) {
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

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_certificate_deserializeCertificateId return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;

}

#endif				/* ENABLE_PKCS11H_CERTIFICATE */

