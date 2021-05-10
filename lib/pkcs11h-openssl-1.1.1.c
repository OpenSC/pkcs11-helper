/*
 * Copyright (c) 2005-2018 Alon Bar-Lev <alon.barlev@gmail.com>
 * Copyright (c) 2021 Selva Nair <selva.nair@gmail.com>
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

#if defined(ENABLE_PKCS11H_OPENSSL)

#include <pkcs11-helper-1.0/pkcs11h-openssl.h>
#include "_pkcs11h-core.h"
#include "_pkcs11h-mem.h"

#include <openssl/engine.h>

#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif

#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif

struct pkcs11h_openssl_session_s {
#if defined(ENABLE_PKCS11H_THREADING)
	_pkcs11h_mutex_t reference_count_lock;
#endif
	volatile int reference_count;
	X509 *x509;
	pkcs11h_certificate_t certificate;
	pkcs11h_hook_openssl_cleanup_t cleanup_hook;
};

static struct {
	EVP_PKEY_METHOD *pmeth_rsa;
	int rsa_index;
	EVP_PKEY_METHOD *pmeth_dsa;
	int dsa_index;
	EVP_PKEY_METHOD *pmeth_ec;
	int eckey_index;
	ENGINE *engine;
} __openssl_methods;

int
__pkcs11h_openssl_ex_data_dup (
	CRYPTO_EX_DATA *to,
	const CRYPTO_EX_DATA *from,
	void *from_d,
	int idx,
	long argl,
	void *argp
) {
	pkcs11h_openssl_session_t openssl_session;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_ex_data_dup entered - to=%p, from=%p, from_d=%p, idx=%d, argl=%ld, argp=%p",
		(void *)to,
		(void *)from,
		from_d,
		idx,
		argl,
		argp
	);

	_PKCS11H_ASSERT (from_d!=NULL);

	if ((openssl_session = *(pkcs11h_openssl_session_t *)from_d) != NULL) {
		_PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: __pkcs11h_openssl_ex_data_dup session refcount=%d",
			openssl_session->reference_count
		);
		openssl_session->reference_count++;
	}

	return 1;
}

static
void
__pkcs11h_openssl_ex_data_free (
	void *parent,
	void *ptr,
	CRYPTO_EX_DATA *ad,
	int idx,
	long argl,
	void *argp
) {
	pkcs11h_openssl_session_t openssl_session = (pkcs11h_openssl_session_t)ptr;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_ex_data_free entered - parent=%p, ptr=%p, ad=%p, idx=%d, argl=%ld, argp=%p",
		parent,
		ptr,
		(void *)ad,
		idx,
		argl,
		argp
	);

	if (openssl_session != NULL) {
		pkcs11h_openssl_freeSession (openssl_session);
	}
}


static
pkcs11h_certificate_t
__pkcs11h_openssl_get_pkcs11h_certificate (
	IN EVP_PKEY *pkey
) {
	pkcs11h_openssl_session_t session = NULL;

	_PKCS11H_ASSERT (pkey!=NULL);

	switch (EVP_PKEY_id(pkey)) {
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:
		{
			const RSA *rsa = EVP_PKEY_get0_RSA (pkey);
			_PKCS11H_ASSERT (rsa!=NULL);
			session = (pkcs11h_openssl_session_t)RSA_get_ex_data (rsa, __openssl_methods.rsa_index);
		}
		break;
#endif
#ifndef OPENSSL_NO_DSA
		case EVP_PKEY_DSA:
		{
			DSA *dsa = EVP_PKEY_get0_DSA (pkey);
			_PKCS11H_ASSERT (dsa!=NULL);
			session = (pkcs11h_openssl_session_t)DSA_get_ex_data (dsa, __openssl_methods.dsa_index);
		}
		break;
#endif
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
		{
			const EC_KEY *ec = EVP_PKEY_get0_EC_KEY (pkey);
			_PKCS11H_ASSERT (ec!=NULL);
			session = (pkcs11h_openssl_session_t)EC_KEY_get_ex_data (ec, __openssl_methods.eckey_index);
		}
		break;
#endif
		default:
			/* unknown key type: die in assert below */
			_PKCS11H_LOG (PKCS11H_LOG_ERROR, "PKCS#11: Unknown key type (%d)", EVP_PKEY_id(pkey));
		break;
	}

	_PKCS11H_ASSERT (session!=NULL);
	_PKCS11H_ASSERT (session->certificate!=NULL);

	return session->certificate;
}

#ifndef OPENSSL_NO_RSA

static
PKCS11H_BOOL
__pkcs11h_md2ck (
	IN const EVP_MD * const md,
	OUT CK_MECHANISM_TYPE * const hash_alg,
	IN PKCS11H_BOOL is_mgf
)
{
	PKCS11H_BOOL ret = TRUE;

	_PKCS11H_ASSERT(md!=NULL);
	_PKCS11H_ASSERT(hash_alg!=NULL);

	switch (EVP_MD_type(md)) {
		case NID_sha1:
			*hash_alg = is_mgf ? CKG_MGF1_SHA1 : CKM_SHA_1;
		break;
		case NID_sha224:
			*hash_alg = is_mgf ? CKG_MGF1_SHA224 : CKM_SHA224;
		break;
		case NID_sha256:
			*hash_alg = is_mgf ? CKG_MGF1_SHA256 : CKM_SHA256;
		break;
		case NID_sha384:
			*hash_alg = is_mgf ? CKG_MGF1_SHA384 : CKM_SHA384;
		break;
		case NID_sha512:
			*hash_alg = is_mgf ? CKG_MGF1_SHA512 : CKM_SHA512;
		break;
		default:
			_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Unknown digest type (%d)", EVP_MD_type(md));
			ret = FALSE;
		break;
	}
	return ret;
}

static
PKCS11H_BOOL
__pkcs11h_get_ossl_pss_params (
	IN EVP_PKEY_CTX *ctx,
	OUT EVP_MD **md,
	OUT EVP_MD **mgf1_md,
	OUT int * const saltlen
)
{
	PKCS11H_BOOL ret = FALSE;

	_PKCS11H_ASSERT (ctx!=NULL);
	_PKCS11H_ASSERT (md!=NULL);
	_PKCS11H_ASSERT (mgf1_md!=NULL);
	_PKCS11H_ASSERT (saltlen!=NULL);

	if (
		(EVP_PKEY_CTX_get_signature_md (ctx, md) <= 0) ||
		(EVP_PKEY_CTX_get_rsa_mgf1_md (ctx, mgf1_md) <= 0) ||
		(EVP_PKEY_CTX_get_rsa_pss_saltlen (ctx, saltlen) <= 0) ||
		(*md == NULL) || (*mgf1_md == NULL)
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: failed to get pss params from ctx");
		goto done;
	}
	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: __pkcs11h_get_pss_params: saltlen=%d md=%s mgf1_md=%s",
		*saltlen, EVP_MD_name (*md), EVP_MD_name (*mgf1_md)
	);

	ret = TRUE;

done:
	return ret;
}

static
PKCS11H_BOOL
__pkcs11h_get_pss_params (
	IN EVP_PKEY_CTX *ctx,
	OUT CK_RSA_PKCS_PSS_PARAMS *params
) {

	EVP_MD *md, *mgf1_md;
	int saltlen;
	EVP_PKEY *pkey;
	PKCS11H_BOOL ret = FALSE;

	_PKCS11H_ASSERT (ctx!=NULL);
	_PKCS11H_ASSERT (params!=NULL);

	pkey = EVP_PKEY_CTX_get0_pkey (ctx);
	if (pkey==NULL) {
		goto done;
	}

	if (!__pkcs11h_get_ossl_pss_params (ctx, &md, &mgf1_md, &saltlen)) {
		goto done;
	}

	if (saltlen == RSA_PSS_SALTLEN_DIGEST) {
		saltlen = EVP_MD_size (md);
	}
	else if ((saltlen == RSA_PSS_SALTLEN_MAX) || (saltlen == RSA_PSS_SALTLEN_MAX_SIGN)) {
		saltlen = EVP_PKEY_size (pkey) - EVP_MD_size (md) - 2;
	}
	if (((EVP_PKEY_bits (pkey) - 1) & 0x7) == 0) {
		saltlen -= 1;
	}
	if (saltlen < 0) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: pss invalid saltlen < 0 (%d)", saltlen);
		goto done;
	}

	memset (params, 0, sizeof(CK_RSA_PKCS_PSS_PARAMS));
	params->sLen = saltlen;
	if (
		__pkcs11h_md2ck (md, &params->hashAlg, FALSE) &&
		__pkcs11h_md2ck (mgf1_md, &params->mgf, TRUE)
	) {
		ret = TRUE;
	}

done:
	return ret;
}

static
PKCS11H_BOOL
__pkcs11h_get_oaep_params(
	IN EVP_PKEY_CTX *ctx,
	OUT CK_RSA_PKCS_OAEP_PARAMS *params
)
{
	const EVP_MD *md, *mgf1_md;
	int len = 0;
	unsigned char * label = NULL;
	PKCS11H_BOOL ret = FALSE;

	_PKCS11H_ASSERT(ctx!=NULL);
	_PKCS11H_ASSERT(params!=NULL);

	if (
		(EVP_PKEY_CTX_get_rsa_oaep_md (ctx, &md) <= 0) ||
		(EVP_PKEY_CTX_get_rsa_mgf1_md (ctx, &mgf1_md) <= 0) ||
		(md == NULL) || (mgf1_md == NULL)
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: failed to get oaep params from ctx");
		goto done;
	}
	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: __pkcs11h_get_oaep_params: md=%s mgf1_md=%s",
		EVP_MD_name (md), EVP_MD_name (mgf1_md)
	);

	memset (params, 0, sizeof (CK_RSA_PKCS_OAEP_PARAMS));

	if ((len = EVP_PKEY_CTX_get0_rsa_oaep_label (ctx, &label)) > 0) {
		params->source = CKZ_DATA_SPECIFIED;
		params->pSourceData = label;
		params->ulSourceDataLen = len;
	}

	if (
		__pkcs11h_md2ck (md, &params->hashAlg, FALSE) &&
		__pkcs11h_md2ck (mgf1_md, &params->mgf, TRUE)
	) {
		ret = TRUE;
	}

done:
	return ret;
}

/* return 1 on success -1 on error */
static
int
__pkcs11h_openssl_pkey_rsa_decrypt(
	IN EVP_PKEY_CTX *ctx,
	OUT unsigned char *to,
	IN OUT size_t *tlen,
	IN const unsigned char *from,
	IN size_t flen
)
{
	pkcs11h_certificate_t certificate;
	PKCS11H_BOOL session_locked = FALSE;
	CK_RV rv = CKR_FUNCTION_FAILED;
	EVP_PKEY *pkey;
	int padding;
	size_t tlen_tmp;
	CK_MECHANISM mech = {CKM_RSA_PKCS, NULL, 0};
	CK_RSA_PKCS_OAEP_PARAMS oaep_params = {0};

	_PKCS11H_ASSERT(ctx!=NULL);
	_PKCS11H_ASSERT (from!=NULL);
	_PKCS11H_ASSERT (to!=NULL);
	_PKCS11H_ASSERT(tlen!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_pkey_rsa_decrypt entry - ctx=%p, to=%p, *tlen="P_Z", from=%p, flen="P_Z"",
		(void*)ctx,
		to,
		*tlen,
		from,
		flen
	);

	tlen_tmp = *tlen;
	EVP_PKEY_CTX_get_rsa_padding (ctx, &padding);

	pkey = EVP_PKEY_CTX_get0_pkey (ctx);
	if (pkey==NULL) {
		goto cleanup;
	}

	switch (padding) {
		case RSA_PKCS1_PADDING:
			mech.mechanism = CKM_RSA_PKCS;
		break;
		case RSA_PKCS1_OAEP_PADDING:
			mech.mechanism = CKM_RSA_PKCS_OAEP;
			if (!__pkcs11h_get_oaep_params(ctx, &oaep_params)) {
				goto cleanup;
			}
			mech.pParameter = &oaep_params;
			mech.ulParameterLen = sizeof(oaep_params);
		break;
		case RSA_NO_PADDING:
			mech.mechanism = CKM_RSA_X_509;
		break;
		default:
			rv = CKR_MECHANISM_INVALID;
		break;
	}
	if (rv == CKR_MECHANISM_INVALID)
		goto cleanup;

	certificate = __pkcs11h_openssl_get_pkcs11h_certificate (pkey);
	if ((rv = pkcs11h_certificate_lockSession (certificate)) != CKR_OK) {
		goto cleanup;
	}
	session_locked = TRUE;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: __pkcs11h_openssl_pkey_rsa_decrypt operation with mechanism_type = %ld",
		mech.mechanism
	);

	if (
		(rv = pkcs11h_certificate_decryptAny_ex (
			certificate,
			&mech,
			from,
			flen,
			to,
			&tlen_tmp
		)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform decryption %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	*tlen = tlen_tmp;

cleanup:

	if (session_locked) {
		pkcs11h_certificate_releaseSession (certificate);
		session_locked = FALSE;
	}
	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_pkey_rsa_decrypt - return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK ? 1 : -1;
}

/* Add PKCS1 DigestInfo to tbs and return the result in *enc.
 * Returns false on error, true  on success. The caller must free *enc
 * by calling _pkcs11h_mem_free(enc);
 */
static
PKCS11H_BOOL
__pkcs11h_encode_pkcs1 (
	OUT unsigned char **enc,
	OUT size_t *enc_len,
	IN int type,
	IN const unsigned char *tbs,
	IN size_t tbslen
)
{
	unsigned char *out=NULL;
	unsigned char *ptr;
	int out_len = 0;
	int tmp_len;
	X509_ALGOR *algor = NULL;
	ASN1_STRING *digest = NULL;

	_PKCS11H_ASSERT(enc!=NULL);
	_PKCS11H_ASSERT(enc_len!=NULL);
	_PKCS11H_ASSERT(tbs!=NULL);

	_PKCS11H_LOG(
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: encode_pkcs1 entry enc=%p, enc_len=%p, md_type=%d, tbs=%p, tbslen="P_Z"",
		(void*)enc, (void*)enc_len, type, tbs, tbslen
	);

	if (
		(algor = X509_ALGOR_new()) == NULL ||
		(X509_ALGOR_set0 (algor, OBJ_nid2obj(type), V_ASN1_NULL, NULL) <= 0) ||
		(digest = ASN1_STRING_type_new(V_ASN1_OCTET_STRING)) == NULL ||
		(ASN1_STRING_set(digest, tbs, tbslen) <= 0)
	) {
		_PKCS11H_LOG(PKCS11H_LOG_WARN, "PKCS#11: OpenSSL memory alloc error");
		goto cleanup;
	}

	if (algor->algorithm == NULL || OBJ_length(algor->algorithm) == 0) {
		_PKCS11H_LOG(PKCS11H_LOG_WARN, "PKCS#11: Invalid digest algorithm (type = %d)", type);
		goto cleanup;
	}

	/* We want DER encoding of X509_SIG = {algor, digest} which could be
	 * computed as i2d_X509_SIG(), but, unfortunately, the X509_SIG struct
	 * is opaque and has no constructor. Hence we combine the two elements
	 * into a sequence ourselves -- not pretty
	 */

	/* find required size for the buffer */
	if ((tmp_len = i2d_X509_ALGOR (algor, NULL)) < 0)
		goto cleanup;
	out_len = tmp_len;

	if ((tmp_len = i2d_ASN1_OCTET_STRING (digest, NULL)) < 0)
		goto cleanup;
	out_len += tmp_len + 2 ; /* extra 2 bytes for sequence header added below */

	if (_pkcs11h_mem_malloc ((void *)&out, out_len) != CKR_OK) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot allocate memory");
		goto cleanup;
	}

	ptr = out;
	*ptr++ = V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED;
	*ptr++ = out_len - 2;

	/* compute and append the DER of algor and digest to ptr */
	i2d_X509_ALGOR(algor, &ptr);  /* this advances ptr */
	i2d_ASN1_OCTET_STRING(digest, &ptr);

	*enc_len = out_len;
	*enc = out;
	out = NULL;

	_PKCS11H_LOG(
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: encode_pkcs1 - encoded length = %d", out_len
	);

cleanup:
	if (digest)
		ASN1_STRING_free(digest);
	if (algor)
		X509_ALGOR_free(algor);
	if (out)
		_pkcs11h_mem_free ((void*)&out);

	return (out_len > 0);
}

/* return 1 on success -1 on error */
static
int
__pkcs11h_openssl_pkey_rsa_sign(
	IN EVP_PKEY_CTX *ctx,
	OUT unsigned char *sig,
	IN OUT size_t *siglen,
	IN const unsigned char *tbs,
	IN size_t tbslen
)
{
	pkcs11h_certificate_t certificate;
	PKCS11H_BOOL session_locked = FALSE;
	CK_RV rv = CKR_FUNCTION_FAILED;

	CK_MECHANISM mech = {CKM_RSA_PKCS, NULL, 0};
	EVP_PKEY *pkey;
	CK_RSA_PKCS_PSS_PARAMS pss_params = {0};

	const unsigned char *from = tbs;
	size_t from_len = tbslen;
	unsigned char *encoded = NULL;
	size_t enc_len = 0;
	int padding;
	size_t siglen_tmp;

	_PKCS11H_ASSERT (ctx!=NULL);
	_PKCS11H_ASSERT (sig!=NULL);
	_PKCS11H_ASSERT (siglen!=NULL);
	_PKCS11H_ASSERT (tbs!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_pkey_rsa_sign entry - ctx=%p, sig=%p, *siglen="P_Z", tbs=%p, tbslen="P_Z"",
		(void*)ctx,
		sig,
		*siglen,
		tbs,
		tbslen
	);

	siglen_tmp = *siglen;
	EVP_PKEY_CTX_get_rsa_padding (ctx, &padding);

	pkey = EVP_PKEY_CTX_get0_pkey (ctx);
	if (pkey == NULL) {
		goto cleanup;
	}

	switch (padding) {
		case RSA_PKCS1_PADDING:
		{
			EVP_MD *md;
			int md_type;
			if (EVP_PKEY_CTX_get_signature_md (ctx, &md) <= 0) {
				_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: unknown signature MD");
				goto cleanup;
			}

			mech.mechanism = CKM_RSA_PKCS;
			md_type = EVP_MD_type(md);

			if (md_type != NID_md5_sha1) { /* Add DigestInfo to tbs */
				if (__pkcs11h_encode_pkcs1 (&encoded, &enc_len, md_type, tbs, tbslen)) {
					from = encoded;
					from_len = enc_len;
				}
				else {
					_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: PKCS1 encoding failed");
					goto cleanup;
				}
			}
		}
		break;
		case RSA_PKCS1_PSS_PADDING:
			mech.mechanism = CKM_RSA_PKCS_PSS;
			if (!__pkcs11h_get_pss_params (ctx, &pss_params)) {
				goto cleanup;
			}
			mech.pParameter = &pss_params;
			mech.ulParameterLen = sizeof(pss_params);
		break;
		case RSA_NO_PADDING:
			mech.mechanism = CKM_RSA_X_509;
		break;
		default:
			rv = CKR_MECHANISM_INVALID;
		break;
	}

	if (rv == CKR_MECHANISM_INVALID) {
		goto cleanup;
	}

	certificate = __pkcs11h_openssl_get_pkcs11h_certificate (pkey);
	if ((rv = pkcs11h_certificate_lockSession (certificate)) != CKR_OK) {
		goto cleanup;
	}
	session_locked = TRUE;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: __pkcs11h_openssl_pkey_rsa_sign performing signature with mechanism_type = %ld",
		mech.mechanism
	);

	/* at this point from points to tbs or encoded tbs */
	if (
		(rv = pkcs11h_certificate_signAny_ex (
			certificate,
			&mech,
			from,
			from_len,
			sig,
			&siglen_tmp
		)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	*siglen = siglen_tmp;

cleanup:
	if (session_locked) {
		pkcs11h_certificate_releaseSession (certificate);
		session_locked = FALSE;
	}
	if (encoded) {
		memset(encoded, 0, enc_len);
		_pkcs11h_mem_free((void*)&encoded);
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: __pkcs11h_openssl_pkey_rsa_sign - return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK ? 1 : -1;
}

static
PKCS11H_BOOL
__pkcs11h_openssl_session_setRSA(
	IN const pkcs11h_openssl_session_t openssl_session,
	IN EVP_PKEY * evp
) {
	PKCS11H_BOOL ret = FALSE;
	RSA *rsa = NULL;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_session_setRSA - entered openssl_session=%p, evp=%p",
		(void *)openssl_session,
		(void *)evp
	);

	if (
		(rsa = EVP_PKEY_get1_RSA (evp)) == NULL
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get RSA key");
		goto cleanup;
	}

	RSA_set_ex_data (rsa, __openssl_methods.rsa_index, openssl_session);
	EVP_PKEY_set1_engine(evp, __openssl_methods.engine);

	ret = TRUE;

cleanup:

	if (rsa != NULL) {
		RSA_free (rsa);
		rsa = NULL;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_session_setRSA - return ret=%d",
		ret
	);

	return ret;
}

#endif

#ifndef OPENSSL_NO_DSA
/*
 * Helper to convert DSA signature returned by PKCS11
 * to the DER encoding of DSA_SIG structure.
 * On entry buf of length len contains r and s concatenated.
 * The result is in *to if it fits within *tlen characters.
 * On return tlen is updated to output size.
 * Returns TRUE on success FALSE on error.
 */
static
PKCS11H_BOOL
__pkcs11h_dsa_bin2der(
	IN const unsigned char * const buf,
	IN const size_t len,
	OUT unsigned char **to,
	IN OUT size_t * const tlen
)
{
	DSA_SIG *dsasig = NULL;
	BIGNUM *r = BN_bin2bn(buf, len/2, NULL);
	BIGNUM *s = BN_bin2bn(buf+len/2, len/2, NULL);
	int out_len = 0;

	_PKCS11H_ASSERT(to!=NULL);
	_PKCS11H_ASSERT(tlen!=NULL);

	_PKCS11H_LOG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_dsa_bin2der - entry buf=%p, len="P_Z", to=%p, *tlen="P_Z"",
		buf, len, (void*)to, *tlen
	);

	if (!r || !s) {
		goto cleanup;
	}
	dsasig = DSA_SIG_new();
	if (!dsasig) {
		goto cleanup;
	}
	if (!DSA_SIG_set0(dsasig, r, s)) {
		goto cleanup;
	}

	out_len = i2d_DSA_SIG(dsasig, NULL);
	if (out_len > (int)*tlen) {
		_PKCS11H_LOG ( PKCS11H_LOG_WARN, "PKCS#11: DER encoded DSA signature is too long (%d bytes)", out_len);
		out_len = 0;
		goto cleanup;
	}
	out_len = i2d_DSA_SIG(dsasig, to);
	if (out_len > 0)
		*tlen = (size_t)out_len;
cleanup:
	if (dsasig) {
		DSA_SIG_free(dsasig);
	}
	else {
		BN_free(r); /* it is ok to free NULL BN */
		BN_free(s);
	}
	_PKCS11H_LOG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_dsa_bin2der - leaving out_len = %d, *tlen="P_Z"",
		out_len, *tlen
	);
	return (out_len > 0);
}

static
PKCS11H_BOOL
__pkcs11h_openssl_session_setDSA(
	IN const pkcs11h_openssl_session_t openssl_session,
	IN EVP_PKEY * evp
) {
	PKCS11H_BOOL ret = FALSE;
	DSA *dsa = NULL;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_session_setDSA - entered openssl_session=%p, evp=%p",
		(void *)openssl_session,
		(void *)evp
	);

	if (
		(dsa = EVP_PKEY_get1_DSA (evp)) == NULL
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get DSA key");
		goto cleanup;
	}

	DSA_set_ex_data (dsa, __openssl_methods.dsa_index, openssl_session);
	EVP_PKEY_set1_engine(evp, __openssl_methods.engine);

	ret = TRUE;

cleanup:

	if (dsa != NULL) {
		DSA_free (dsa);
		dsa = NULL;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_session_setDSA - return ret=%d",
		ret
	);

	return ret;
}

#endif

#ifndef OPENSSL_NO_EC

/*
 * Helper to convert ECDSA signature returned by PKCS11
 * to DER encoding of ECDSA_SIG structure.
 * On entry buf of length len contains r and s concatenated.
 * The result is in *to if it fits within *tlen characters.
 * On return tlen is updated to output size.
 * Returns TRUE on success FALSE on error.
 */
static
PKCS11H_BOOL
__pkcs11h_ecdsa_bin2der(
	IN const unsigned char * const buf,
	IN const size_t len,
	OUT unsigned char **to,
	IN OUT size_t * const tlen
)
{
	ECDSA_SIG *ecsig = NULL;
	BIGNUM *r = BN_bin2bn(buf, len/2, NULL);
	BIGNUM *s = BN_bin2bn(buf+len/2, len/2, NULL);
	int out_len = 0;

	_PKCS11H_ASSERT(to!=NULL);
	_PKCS11H_ASSERT(tlen!=NULL);

	_PKCS11H_LOG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_ecdsa_bin2der - entry buf=%p, len="P_Z", to=%p, *tlen="P_Z"",
		buf, len, (void*)to, *tlen
	);

	if (!r || !s) {
		goto cleanup;
	}
	ecsig = ECDSA_SIG_new();
	if (!ecsig) {
		goto cleanup;
	}
	if (!ECDSA_SIG_set0(ecsig, r, s)) { /* ecsig takes ownership of r and s */
		goto cleanup;
	}

	out_len = i2d_ECDSA_SIG(ecsig, NULL);
	if (out_len > (int) *tlen) {
		_PKCS11H_LOG ( PKCS11H_LOG_WARN, "PKCS#11: DER encoded ECDSA signature is too long (%d bytes)", out_len );
		out_len = 0;
		goto cleanup;
	}

	out_len = i2d_ECDSA_SIG(ecsig, to);
	if (out_len > 0)
		*tlen = (size_t)out_len;
cleanup:
	if (ecsig) {
		ECDSA_SIG_free(ecsig);
	}
	else {
		BN_free(r); /* it is ok to free NULL BN */
		BN_free(s);
	}
	_PKCS11H_LOG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_ecdsa_bin2der - leaving out_len = %d, *tlen="P_Z"",
		out_len, *tlen
	);
	return (out_len > 0);
}

static
PKCS11H_BOOL
__pkcs11h_openssl_session_setECDSA(
	IN const pkcs11h_openssl_session_t openssl_session,
	IN EVP_PKEY * evp
) {
	PKCS11H_BOOL ret = FALSE;
	EC_KEY *ec = NULL;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_session_setECDSA - entered openssl_session=%p, evp=%p",
		(void *)openssl_session,
		(void *)evp
	);

	if (
		(ec = EVP_PKEY_get1_EC_KEY (evp)) == NULL
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get EC key");
		goto cleanup;
	}

	EC_KEY_set_ex_data (ec, __openssl_methods.eckey_index, openssl_session);
	EVP_PKEY_set1_engine(evp, __openssl_methods.engine);

	ret = TRUE;

cleanup:

	if (ec != NULL) {
		EC_KEY_free (ec);
		ec = NULL;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_session_setECDSA - return ret=%d",
		ret
	);

	return ret;
}

#endif

#if !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_EC)

/* Common method used for EC and DSA */
static
int
__pkcs11h_openssl_pkey_ecdsa_sign(
	IN EVP_PKEY_CTX *ctx,
	OUT unsigned char *sig,
	OUT size_t *siglen,
	IN const unsigned char *tbs,
	IN size_t tbslen
) {
	pkcs11h_certificate_t certificate;
	PKCS11H_BOOL session_locked = FALSE;
	CK_MECHANISM_TYPE mech_type = CKM_ECDSA;
	CK_RV rv = CKR_FUNCTION_FAILED;
	size_t siglen_tmp;
	EVP_PKEY *pkey;
	unsigned char *sig_tmp = NULL;
	size_t siglen_der;

	_PKCS11H_ASSERT (ctx!=NULL);
	/* sig must be non-null as we use EVP_PKEY_FLAG_AUTOARGLEN */
	_PKCS11H_ASSERT (sig!=NULL);
	_PKCS11H_ASSERT (siglen!=NULL);
	_PKCS11H_ASSERT (tbs!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_pkey_ecdsa_sign - entry ctx=%p, sig=%p, *siglen="P_Z", tbs=%p, tbslen="P_Z"",
		(void*)ctx,
		sig,
		*siglen,
		tbs,
		tbslen
	);

	siglen_tmp = *siglen;
	pkey = EVP_PKEY_CTX_get0_pkey (ctx);
	if (pkey == NULL) {
		goto cleanup;
	}

	switch (EVP_PKEY_id(pkey)) {
#ifndef OPENSSL_NO_DSA
		case EVP_PKEY_DSA:
			mech_type = CKM_DSA;
		break;
#endif
#ifndef OPENSSL_NO_EC
		case EVP_PKEY_EC:
			mech_type = CKM_ECDSA;
		break;
#endif
		default:
			rv = CKR_MECHANISM_INVALID;
		break;
	}

	if (rv == CKR_MECHANISM_INVALID)
		goto cleanup;

	certificate = __pkcs11h_openssl_get_pkcs11h_certificate (pkey);
	if ((rv = pkcs11h_certificate_lockSession (certificate)) != CKR_OK) {
		goto cleanup;
	}
	session_locked = TRUE;

	/* OpenSSL expects DER encoded signature in sig which is always
	 * longer than the signature generated by PKCS#11 -- FWIW, we
	 * still check and allocate a temp buffer.
	 */
	if (
		(rv = pkcs11h_certificate_signAny (
			certificate,
			mech_type,
			tbs,
			tbslen,
			NULL,
			&siglen_tmp
		)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if (
		_pkcs11h_mem_malloc (
			(void*)&sig_tmp,
			siglen_tmp) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot allocate memory");
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_signAny (
			certificate,
			mech_type,
			tbs,
			tbslen,
			sig_tmp,
			&siglen_tmp
		)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	/* convert PKCS#11 signature to DER encoded byte array expected by OpenSSL */

	siglen_der = EVP_PKEY_size(pkey);
	rv = CKR_FUNCTION_FAILED;

	if (0) {
	}
#ifndef OPENSSL_NO_DSA
	else if (EVP_PKEY_id(pkey) == EVP_PKEY_DSA) {
		if (!__pkcs11h_dsa_bin2der(sig_tmp, siglen_tmp, &sig, &siglen_der))
			goto cleanup;
	}
#endif
#ifndef OPENSSL_NO_EC
	else if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
		if (!__pkcs11h_ecdsa_bin2der(sig_tmp, siglen_tmp, &sig, &siglen_der))
			goto cleanup;
	}
#endif
	rv = CKR_OK;
	*siglen = siglen_der;

cleanup:
	if (session_locked) {
		pkcs11h_certificate_releaseSession (certificate);
		session_locked = FALSE;
	}
	if (sig_tmp)
		_pkcs11h_mem_free ((void*)&sig_tmp);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: __pkcs11h_openssl_pkey_ecdsa_sign - return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK ? 1 : -1;
}

#endif

/* return number of nids or 1 on success, 0 on error */
static
int
__pkcs11h_pkey_meths(
	IN  ENGINE * const e,
	OUT EVP_PKEY_METHOD **pmeth,
	OUT int const **nids,
	IN const int nid
) {

	int ret = 0;
	static int supported_nids[3];
	static int num_nids = 0;

	if (num_nids == 0) {
#ifndef OPENSSL_NO_RSA
		supported_nids[num_nids++] = EVP_PKEY_RSA;
#endif
#ifndef OPENSSL_NO_DSA
		supported_nids[num_nids++] = EVP_PKEY_DSA;
#endif
#ifndef OPENSSL_NO_EC
		supported_nids[num_nids++] = EVP_PKEY_EC;
#endif
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_pkey_meths entry - engine=%p, pmeth=%p, nids=%p, nid=%d",
		(void *)e,
		(void *)pmeth,
		(void *)nids,
		nid
	);

	if (!pmeth && !nids) { /* not expected to happen */
		goto done;
	}

	if (!pmeth) {
		*nids = supported_nids;
		ret = num_nids;
		goto done;
	}

	switch (nid) {
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:
			*pmeth =  __openssl_methods.pmeth_rsa;
		break;
#endif
#ifndef OPENSSL_NO_DSA
		case EVP_PKEY_DSA:
			*pmeth =  __openssl_methods.pmeth_dsa;
		break;
#endif
#ifndef OPENSSL_NO_DSA
		case EVP_PKEY_EC:
			*pmeth =  __openssl_methods.pmeth_ec;
		break;
#endif
		default:
			*pmeth = NULL;
		break;
	}
	ret = (*pmeth != NULL) ? 1 : 0;

done:
	return ret;
}

static
void
__pkcs11h_engine_delete (void) {

	if (__openssl_methods.engine) {
		ENGINE_set_pkey_meths (__openssl_methods.engine, NULL);
		ENGINE_free (__openssl_methods.engine);
		__openssl_methods.engine = NULL;
	}
}

static
PKCS11H_BOOL
__pkcs11h_engine_create (void) {

	PKCS11H_BOOL ret = FALSE;
	ENGINE *e;

	if (__openssl_methods.engine) {
		ret = TRUE; /* already initialized */
		goto done;
	}

	e = ENGINE_new ();

	if (
		!e ||
		!ENGINE_set_id (e, "pkc11-helper") ||
		!ENGINE_set_name (e, "PKCS11 helper internal engine") ||
		!ENGINE_set_pkey_meths (e, __pkcs11h_pkey_meths)
	) {
		ENGINE_free (e);
		e = NULL;
		goto done;
	}
	__openssl_methods.engine = e;
	ret = TRUE;

done:
	return ret;
}

PKCS11H_BOOL
_pkcs11h_openssl_initialize (void) {

	PKCS11H_BOOL ret = FALSE;
	const EVP_PKEY_METHOD *pmeth_orig;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_initialize - entered"
	);

#ifndef OPENSSL_NO_RSA
	__openssl_methods.rsa_index = RSA_get_ex_new_index (
		0,
		"pkcs11h",
		NULL,
		__pkcs11h_openssl_ex_data_dup,
		__pkcs11h_openssl_ex_data_free
	);
	if (
		(__openssl_methods.pmeth_rsa == NULL) &&
		((__openssl_methods.pmeth_rsa = EVP_PKEY_meth_new (EVP_PKEY_RSA, EVP_PKEY_FLAG_AUTOARGLEN)) == NULL)
	) {
		goto cleanup;
	}
	pmeth_orig = EVP_PKEY_meth_find (EVP_PKEY_RSA);
	EVP_PKEY_meth_copy (__openssl_methods.pmeth_rsa, pmeth_orig);
	EVP_PKEY_meth_set_sign (__openssl_methods.pmeth_rsa, NULL,
		__pkcs11h_openssl_pkey_rsa_sign);
	EVP_PKEY_meth_set_decrypt (__openssl_methods.pmeth_rsa, NULL,
		__pkcs11h_openssl_pkey_rsa_decrypt);
#endif
#ifndef OPENSSL_NO_DSA
	__openssl_methods.dsa_index = DSA_get_ex_new_index (
		0,
		"pkcs11h",
		NULL,
		__pkcs11h_openssl_ex_data_dup,
		__pkcs11h_openssl_ex_data_free
	);
	if (
		(__openssl_methods.pmeth_dsa == NULL) &&
		((__openssl_methods.pmeth_dsa = EVP_PKEY_meth_new (EVP_PKEY_DSA, EVP_PKEY_FLAG_AUTOARGLEN)) == NULL)
	) {
		goto cleanup;
	}
	pmeth_orig = EVP_PKEY_meth_find (EVP_PKEY_DSA);
	EVP_PKEY_meth_copy (__openssl_methods.pmeth_dsa, pmeth_orig);
	EVP_PKEY_meth_set_sign (__openssl_methods.pmeth_dsa, NULL,
		__pkcs11h_openssl_pkey_ecdsa_sign);
#endif
#ifndef OPENSSL_NO_EC
	__openssl_methods.eckey_index = EC_KEY_get_ex_new_index (
		0,
		"pkcs11h",
		NULL,
		__pkcs11h_openssl_ex_data_dup,
		__pkcs11h_openssl_ex_data_free
	);
	if (
		(__openssl_methods.pmeth_ec == NULL) &&
		((__openssl_methods.pmeth_ec = EVP_PKEY_meth_new (EVP_PKEY_EC, EVP_PKEY_FLAG_AUTOARGLEN)) == NULL)
	) {
		goto cleanup;
	}
	pmeth_orig = EVP_PKEY_meth_find (EVP_PKEY_EC);
	EVP_PKEY_meth_copy (__openssl_methods.pmeth_ec, pmeth_orig);
	EVP_PKEY_meth_set_sign (__openssl_methods.pmeth_ec, NULL,
		__pkcs11h_openssl_pkey_ecdsa_sign);
#endif
	if (!__pkcs11h_engine_create())
		goto cleanup;

	ret = TRUE;

cleanup:
	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_initialize - return %d",
		ret
	);
	return ret;
}

PKCS11H_BOOL
_pkcs11h_openssl_terminate (void) {

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_terminate"
	);
	__pkcs11h_engine_delete();
#ifndef OPENSSL_NO_RSA
	if (__openssl_methods.pmeth_rsa != NULL) {
		EVP_PKEY_meth_free (__openssl_methods.pmeth_rsa);
		__openssl_methods.pmeth_rsa = NULL;
	}
#endif
#ifndef OPENSSL_NO_DSA
	if (__openssl_methods.pmeth_dsa != NULL) {
		EVP_PKEY_meth_free (__openssl_methods.pmeth_dsa);
		__openssl_methods.pmeth_dsa = NULL;
	}
#endif
#ifndef OPENSSL_NO_EC
	if (__openssl_methods.pmeth_ec != NULL) {
		EVP_PKEY_meth_free (__openssl_methods.pmeth_ec);
		__openssl_methods.pmeth_ec = NULL;
	}
#endif
	return TRUE;
}

X509 *
pkcs11h_openssl_getX509 (
	IN const pkcs11h_certificate_t certificate
) {
	unsigned char *certificate_blob = NULL;
	size_t certificate_blob_size = 0;
	X509 *x509 = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;
	const unsigned char * d2i1 = NULL;

	_PKCS11H_ASSERT (certificate!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getX509 - entry certificate=%p",
		(void *)certificate
	);

	if ((x509 = X509_new ()) == NULL) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Unable to allocate certificate object");
		rv = CKR_HOST_MEMORY;
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_getCertificateBlob (
			certificate,
			NULL,
			&certificate_blob_size
		)) != CKR_OK
	) {
		goto cleanup;
	}

	if ((rv = _pkcs11h_mem_malloc ((void *)&certificate_blob, certificate_blob_size)) != CKR_OK) {
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_getCertificateBlob (
			certificate,
			certificate_blob,
			&certificate_blob_size
		)) != CKR_OK
	) {
		goto cleanup;
	}

	d2i1 = (const unsigned char *)certificate_blob;
	if (!d2i_X509 (&x509, &d2i1, certificate_blob_size)) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Unable to parse X.509 certificate");
		rv = CKR_FUNCTION_FAILED;
		goto cleanup;
	}

	rv = CKR_OK;

cleanup:

	if (certificate_blob != NULL) {
		_pkcs11h_mem_free((void *)&certificate_blob);
	}

	if (rv != CKR_OK) {
		if (x509 != NULL) {
			X509_free (x509);
			x509 = NULL;
		}
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_getX509 - return rv=%ld-'%s', x509=%p",
		rv,
		pkcs11h_getMessage (rv),
		(void *)x509
	);

	return x509;
}

pkcs11h_openssl_session_t
pkcs11h_openssl_createSession (
	IN const pkcs11h_certificate_t certificate
) {
	pkcs11h_openssl_session_t openssl_session = NULL;
	CK_RV rv;
	PKCS11H_BOOL ok = FALSE;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_createSession - entry"
	);

	if (
		_pkcs11h_mem_malloc (
			(void*)&openssl_session,
			sizeof (struct pkcs11h_openssl_session_s)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot allocate memory");
		goto cleanup;
	}

	openssl_session->certificate = certificate;
	openssl_session->reference_count = 1;

#if defined(ENABLE_PKCS11H_THREADING)
	if ((rv = _pkcs11h_threading_mutexInit(&openssl_session->reference_count_lock)) != CKR_OK) {
		_PKCS11H_LOG (PKCS11H_LOG_ERROR, "PKCS#11: Cannot initialize mutex %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}
#endif

	ok = TRUE;

cleanup:

	if (!ok) {
		_pkcs11h_mem_free ((void *)&openssl_session);
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_createSession - return openssl_session=%p",
		(void *)openssl_session
	);

	return openssl_session;
}

pkcs11h_hook_openssl_cleanup_t
pkcs11h_openssl_getCleanupHook (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	_PKCS11H_ASSERT (openssl_session!=NULL);

	return openssl_session->cleanup_hook;
}

void
pkcs11h_openssl_setCleanupHook (
	IN const pkcs11h_openssl_session_t openssl_session,
	IN const pkcs11h_hook_openssl_cleanup_t cleanup
) {
	_PKCS11H_ASSERT (openssl_session!=NULL);

	openssl_session->cleanup_hook = cleanup;
}

void
pkcs11h_openssl_freeSession (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	CK_RV rv;

	_PKCS11H_ASSERT (openssl_session!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_freeSession - entry openssl_session=%p, count=%d",
		(void *)openssl_session,
		openssl_session->reference_count
	);

#if defined(ENABLE_PKCS11H_THREADING)
	if ((rv = _pkcs11h_threading_mutexLock(&openssl_session->reference_count_lock)) != CKR_OK) {
		_PKCS11H_LOG (PKCS11H_LOG_ERROR, "PKCS#11: Cannot lock mutex %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}
#endif
	openssl_session->reference_count--;
#if defined(ENABLE_PKCS11H_THREADING)
	_pkcs11h_threading_mutexRelease(&openssl_session->reference_count_lock);
#endif

	_PKCS11H_ASSERT (openssl_session->reference_count>=0);

	if (openssl_session->reference_count == 0) {
#if defined(ENABLE_PKCS11H_THREADING)
		_pkcs11h_threading_mutexFree(&openssl_session->reference_count_lock);
#endif

		if (openssl_session->cleanup_hook != NULL) {
			openssl_session->cleanup_hook (openssl_session->certificate);
		}

		if (openssl_session->x509 != NULL) {
			X509_free (openssl_session->x509);
			openssl_session->x509 = NULL;
		}
		if (openssl_session->certificate != NULL) {
			pkcs11h_certificate_freeCertificate (openssl_session->certificate);
			openssl_session->certificate = NULL;
		}

		_pkcs11h_mem_free ((void *)&openssl_session);
	}

cleanup:

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_freeSession - return"
	);
}

#ifndef OPENSSL_NO_RSA
RSA *
pkcs11h_openssl_session_getRSA (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	RSA *rsa = NULL;
	RSA *ret = NULL;
	EVP_PKEY *evp = NULL;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_session_getRSA - entry openssl_session=%p",
		(void *)openssl_session
	);

	if ((evp = pkcs11h_openssl_session_getEVP(openssl_session)) == NULL) {
		goto cleanup;
	}

	if (EVP_PKEY_id (evp) != EVP_PKEY_RSA) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Invalid public key algorithm");
		goto cleanup;
	}

	if (
		(rsa = EVP_PKEY_get1_RSA (evp)) == NULL
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get RSA key");
		goto cleanup;
	}

	ret = rsa;
	rsa = NULL;

cleanup:

	/*
	 * openssl objects have reference
	 * count, so release them
	 */
	if (rsa != NULL) {
		RSA_free (rsa);
		rsa = NULL;
	}

	if (evp != NULL) {
		EVP_PKEY_free (evp);
		evp = NULL;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_session_getRSA - return ret=%p",
		(void *)rsa
	);

	return ret;
}
#endif

EVP_PKEY *
pkcs11h_openssl_session_getEVP (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	X509 *x509 = NULL;
	EVP_PKEY *evp = NULL;
	EVP_PKEY *ret = NULL;

	_PKCS11H_ASSERT (openssl_session!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_session_getEVP - entry openssl_session=%p",
		(void *)openssl_session
	);

	/*
	 * Dup x509 so RSA will not hold session x509
	 */
	if ((x509 = pkcs11h_openssl_session_getX509 (openssl_session)) == NULL) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get certificate object");
		goto cleanup;
	}

	if ((evp = X509_get_pubkey (x509)) == NULL) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get public key");
		goto cleanup;
	}

	if (0) {
	}
#ifndef OPENSSL_NO_RSA
	else if (EVP_PKEY_id (evp) == EVP_PKEY_RSA) {
		if (!__pkcs11h_openssl_session_setRSA(openssl_session, evp)) {
			goto cleanup;
		}
	}
#endif
#ifndef OPENSSL_NO_DSA
	else if (EVP_PKEY_id (evp) == EVP_PKEY_DSA) {
		if (!__pkcs11h_openssl_session_setDSA(openssl_session, evp)) {
			goto cleanup;
		}
	}
#endif
#ifndef OPENSSL_NO_EC
	else if (EVP_PKEY_id(evp) == EVP_PKEY_EC) {
		if (!__pkcs11h_openssl_session_setECDSA(openssl_session, evp)) {
			goto cleanup;
		}
	}
#endif
	else {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Invalid public key algorithm %d", EVP_PKEY_id (evp));
		goto cleanup;
	}

#if defined(ENABLE_PKCS11H_THREADING)
	_pkcs11h_threading_mutexLock(&openssl_session->reference_count_lock);
#endif
	openssl_session->reference_count++;
#if defined(ENABLE_PKCS11H_THREADING)
	_pkcs11h_threading_mutexRelease(&openssl_session->reference_count_lock);
#endif

	ret = evp;
	evp = NULL;

cleanup:

	/*
	 * openssl objects have reference
	 * count, so release them
	 */
	if (evp != NULL) {
		EVP_PKEY_free (evp);
		evp = NULL;
	}

	if (x509 != NULL) {
		X509_free (x509);
		x509 = NULL;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_session_getEVP - return ret=%p",
		(void *)ret
	);

	return ret;
}

X509 *
pkcs11h_openssl_session_getX509 (
	IN const pkcs11h_openssl_session_t openssl_session
) {
	X509 *x509 = NULL;
	PKCS11H_BOOL ok = FALSE;

	_PKCS11H_ASSERT (openssl_session!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_session_getX509 - entry openssl_session=%p",
		(void *)openssl_session
	);

	if (
		openssl_session->x509 == NULL &&
		(openssl_session->x509 = pkcs11h_openssl_getX509 (openssl_session->certificate)) == NULL
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot get certificate object");
		goto cleanup;
	}

	if ((x509 = X509_dup (openssl_session->x509)) == NULL) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot duplicate certificate object");
		goto cleanup;
	}

	ok = TRUE;

cleanup:

	if (!ok) {
		if (x509 != NULL) {
			X509_free (x509);
			x509 = NULL;
		}
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: pkcs11h_openssl_session_getX509 - return x509=%p",
		(void *)x509
	);

	return x509;
}

#endif				/* ENABLE_PKCS11H_OPENSSL */
