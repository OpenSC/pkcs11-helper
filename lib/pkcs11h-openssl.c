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

#if defined(ENABLE_PKCS11H_OPENSSL)

#include <pkcs11-helper-1.0/pkcs11h-openssl.h>
#include "_pkcs11h-core.h"
#include "_pkcs11h-mem.h"

#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif

#if !defined(OPENSSL_NO_EC) && defined(ENABLE_PKCS11H_OPENSSL_EC)
#define __ENABLE_EC
#ifdef ENABLE_PKCS11H_OPENSSL_EC_HACK
#include <ecs_locl.h>
#else
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/ecdsa.h>
#else
#include <openssl/ec.h>
#endif
#endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define EC_KEY_METHOD ECDSA_METHOD
#define EC_KEY_get_default_method ECDSA_get_default_method
#define EC_KEY_get_ex_new_index ECDSA_get_ex_new_index
#define EC_KEY_get_ex_data ECDSA_get_ex_data
#define EC_KEY_set_method ECDSA_set_method
#define EC_KEY_set_ex_data ECDSA_set_ex_data
#if defined(ENABLE_PKCS11H_OPENSSL_EC_HACK)
#define EC_KEY_METHOD_new(ecdsa) (EC_KEY_METHOD *)memmove(malloc(sizeof(EC_KEY_METHOD)), ecdsa, sizeof(EC_KEY_METHOD))
#define EC_KEY_METHOD_free(ecdsa) free(ecdsa)
#define ECDSA_METHOD_set_sign(ecdsa, s) ecdsa->ecdsa_do_sign = s
#else
#define EC_KEY_METHOD_free ECDSA_METHOD_free
#define EC_KEY_METHOD_new ECDSA_METHOD_new
#endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x00907000L
#if !defined(RSA_PKCS1_PADDING_SIZE)
#define RSA_PKCS1_PADDING_SIZE 11
#endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x00908000L
typedef unsigned char *__pkcs11_openssl_d2i_t;
#else
typedef const unsigned char *__pkcs11_openssl_d2i_t;
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

#ifndef HAVE_RSA_METH_DUP
static RSA_METHOD *
RSA_meth_dup (const RSA_METHOD *meth)
{
	RSA_METHOD *ret = NULL;
	CK_RV rv;

	rv = _pkcs11h_mem_malloc ((void *)&ret, sizeof (RSA_METHOD));
	if (rv != CKR_OK) {
		goto cleanup;
	}
	memmove (ret, meth, sizeof (RSA_METHOD));

cleanup:

	return ret;
}
#endif

#ifndef HAVE_RSA_METH_FREE
static void
RSA_meth_free (RSA_METHOD *meth)
{
	if (meth != NULL) {
		if (meth->name != NULL) {
			_pkcs11h_mem_free ((void *)&meth->name);
		}
		_pkcs11h_mem_free ((void *)&meth);
	}
}
#endif

#ifndef HAVE_RSA_METH_SET1_NAME
static int
RSA_meth_set1_name (RSA_METHOD *meth, const char *name)
{
	CK_RV rv;
	rv = _pkcs11h_mem_strdup ((void *)&meth->name, name);
	return rv == CKR_OK ? 1 : 0;
}
#endif

#ifndef HAVE_RSA_METH_SET_FLAGS
static int
RSA_meth_set_flags (RSA_METHOD *meth, int flags)
{
	meth->flags = flags;
	return 1;
}
#endif

#ifndef HAVE_RSA_METH_SET_PRIV_ENC
static int
RSA_meth_set_priv_enc (
	RSA_METHOD *meth,
	int (*priv_enc) (
		int flen,
		const unsigned char *from,
		unsigned char *to,
		RSA *rsa,
		int padding
	)
)
{
	meth->rsa_priv_enc = priv_enc;
	return 1;
}
#endif

#ifndef HAVE_RSA_METH_SET_PRIV_DEC
static int
RSA_meth_set_priv_dec(
	RSA_METHOD *meth,
	int (*priv_dec) (
		int flen,
		const unsigned char *from,
		unsigned char *to,
		RSA *rsa,
		int padding
	)
)
{
	meth->rsa_priv_dec = priv_dec;
	return 1;
}
#endif

#ifndef HAVE_DSA_METH_DUP
static DSA_METHOD *
DSA_meth_dup (const DSA_METHOD *meth)
{
	DSA_METHOD *ret = NULL;
	CK_RV rv;

	rv = _pkcs11h_mem_malloc ((void *)&ret, sizeof (DSA_METHOD));
	if (rv != CKR_OK) {
		goto cleanup;
	}
	memmove (ret, meth, sizeof (DSA_METHOD));

cleanup:

	return ret;
}
#endif

#ifndef HAVE_DSA_METH_FREE
static void
DSA_meth_free (DSA_METHOD *meth)
{
	if (meth != NULL) {
		if (meth->name != NULL) {
			_pkcs11h_mem_free ((void *)&meth->name);
		}
		_pkcs11h_mem_free ((void *)&meth);
	}
}
#endif

#ifndef HAVE_DSA_METH_SET1_NAME
static int
DSA_meth_set1_name (DSA_METHOD *meth, const char *name)
{
	CK_RV rv;
	rv = _pkcs11h_mem_strdup ((void *)&meth->name, name);
	return rv == CKR_OK ? 1 : 0;
}
#endif

#ifndef HAVE_DSA_METH_SET_SIGN
static int
DSA_meth_set_sign (DSA_METHOD *meth,
		   DSA_SIG *(*sign) (const unsigned char *, int, DSA *))
{
	meth->dsa_do_sign = sign;
	return 1;
}
#endif

#ifndef HAVE_DSA_SIG_SET0
static int
DSA_SIG_set0 (DSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	BN_clear_free (sig->r);
	BN_clear_free (sig->s);
	sig->r = r;
	sig->s = s;
	return 1;
}
#endif

#ifdef __ENABLE_EC
#ifndef HAVE_ECDSA_SIG_SET0
static int
ECDSA_SIG_set0 (ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
	BN_clear_free (sig->r);
	BN_clear_free (sig->s);
	sig->r = r;
	sig->s = s;
	return 1;
}
#endif

#ifndef HAVE_EC_KEY_METHOD_GET_SIGN
void EC_KEY_METHOD_get_sign(const EC_KEY_METHOD *meth,
	int (**psign)(int type, const unsigned char *dgst,
		int dlen, unsigned char *sig,
		unsigned int *siglen,
		const BIGNUM *kinv, const BIGNUM *r,
		EC_KEY *eckey),
	int (**psign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
		BIGNUM **kinvp, BIGNUM **rp),
	ECDSA_SIG *(**psign_sig)(const unsigned char *dgst,
		int dgst_len,
		const BIGNUM *in_kinv,
		const BIGNUM *in_r,
		EC_KEY *eckey)
) {
	*psign = NULL;
}
#endif

#ifndef HAVE_EC_KEY_METHOD_SET_SIGN
void EC_KEY_METHOD_set_sign(EC_KEY_METHOD *meth,
	int (*sign)(int type, const unsigned char *dgst,
		int dlen, unsigned char *sig,
		unsigned int *siglen,
		const BIGNUM *kinv, const BIGNUM *r,
		EC_KEY *eckey),
	int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in,
		BIGNUM **kinvp, BIGNUM **rp),
	ECDSA_SIG *(*sign_sig)(const unsigned char *dgst,
		int dgst_len,
		const BIGNUM *in_kinv,
		const BIGNUM *in_r,
		EC_KEY *eckey)
) {
	ECDSA_METHOD_set_sign(meth, sign_sig);
}
#endif
#endif

static struct {
#ifndef OPENSSL_NO_RSA
	RSA_METHOD *rsa;
	int rsa_index;
#endif
#ifndef OPENSSL_NO_DSA
	DSA_METHOD *dsa;
	int dsa_index;
#endif
#ifdef __ENABLE_EC
	EC_KEY_METHOD *eckey;
	int eckey_index;
#endif
} __openssl_methods;

#if OPENSSL_VERSION_NUMBER < 0x10100001L
static
int
__pkcs11h_openssl_ex_data_dup (
	CRYPTO_EX_DATA *to,
	CRYPTO_EX_DATA *from,
	void *from_d,
	int idx,
	long argl,
	void *argp
) {
#else
int
__pkcs11h_openssl_ex_data_dup (
	CRYPTO_EX_DATA *to,
	const CRYPTO_EX_DATA *from,
	void *from_d,
	int idx,
	long argl,
	void *argp
) {
#endif
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

#ifndef OPENSSL_NO_RSA

static
pkcs11h_certificate_t
__pkcs11h_openssl_rsa_get_pkcs11h_certificate (
	IN RSA *rsa
) {
	pkcs11h_openssl_session_t session = NULL;

	_PKCS11H_ASSERT (rsa!=NULL);

	session = (pkcs11h_openssl_session_t)RSA_get_ex_data (rsa, __openssl_methods.rsa_index);

	_PKCS11H_ASSERT (session!=NULL);
	_PKCS11H_ASSERT (session->certificate!=NULL);

	return session->certificate;
}

#if OPENSSL_VERSION_NUMBER < 0x00907000L
static
int
__pkcs11h_openssl_rsa_dec (
	IN int flen,
	IN unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
) {
#else
static
int
__pkcs11h_openssl_rsa_dec (
	IN int flen,
	IN const unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
) {
#endif
	pkcs11h_certificate_t certificate = __pkcs11h_openssl_rsa_get_pkcs11h_certificate (rsa);
	PKCS11H_BOOL session_locked = FALSE;
	CK_MECHANISM_TYPE mech = CKM_RSA_PKCS;
	CK_RV rv = CKR_FUNCTION_FAILED;
	size_t tlen = (size_t)flen;

	_PKCS11H_ASSERT (from!=NULL);
	_PKCS11H_ASSERT (to!=NULL);
	_PKCS11H_ASSERT (rsa!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_rsa_dec entered - flen=%d, from=%p, to=%p, rsa=%p, padding=%d",
		flen,
		from,
		to,
		(void *)rsa,
		padding
	);

	switch (padding) {
		case RSA_PKCS1_PADDING:
			mech = CKM_RSA_PKCS;
		break;
		case RSA_PKCS1_OAEP_PADDING:
			mech = CKM_RSA_PKCS_OAEP;
		break;
		case RSA_SSLV23_PADDING:
			rv = CKR_MECHANISM_INVALID;
		break;
		case RSA_NO_PADDING:
			mech = CKM_RSA_X_509;
		break;
		default:
			rv = CKR_MECHANISM_INVALID;
		break;
	}
	if (rv == CKR_MECHANISM_INVALID)
		goto cleanup;

	if ((rv = pkcs11h_certificate_lockSession (certificate)) != CKR_OK) {
		goto cleanup;
	}
	session_locked = TRUE;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Performing decryption"
	);

	if (
		(rv = pkcs11h_certificate_decryptAny (
			certificate,
			mech,
			from,
			flen,
			to,
			&tlen
		)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform decryption %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	rv = CKR_OK;

cleanup:

	if (session_locked) {
		pkcs11h_certificate_releaseSession (certificate);
		session_locked = FALSE;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_rsa_dec - return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK ? (int)tlen : -1;
}

#if OPENSSL_VERSION_NUMBER < 0x00907000L
static
int
__pkcs11h_openssl_rsa_enc (
	IN int flen,
	IN unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
) {
#else
static
int
__pkcs11h_openssl_rsa_enc (
	IN int flen,
	IN const unsigned char *from,
	OUT unsigned char *to,
	IN OUT RSA *rsa,
	IN int padding
) {
#endif
	pkcs11h_certificate_t certificate = __pkcs11h_openssl_rsa_get_pkcs11h_certificate (rsa);
	PKCS11H_BOOL session_locked = FALSE;
	CK_RV rv = CKR_FUNCTION_FAILED;
	size_t tlen;
	CK_MECHANISM_TYPE mech = CKM_RSA_PKCS;

	_PKCS11H_ASSERT (from!=NULL);
	_PKCS11H_ASSERT (to!=NULL);
	_PKCS11H_ASSERT (rsa!=NULL);

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_rsa_enc entered - flen=%d, from=%p, to=%p, rsa=%p, padding=%d",
		flen,
		from,
		to,
		(void *)rsa,
		padding
	);

	switch (padding) {
		case RSA_PKCS1_PADDING:
			mech = CKM_RSA_PKCS;
		break;
		case RSA_NO_PADDING:
			mech = CKM_RSA_X_509;
		break;
		default:
			rv = CKR_MECHANISM_INVALID;
			goto cleanup;
	}

	tlen = (size_t)RSA_size(rsa);

	if ((rv = pkcs11h_certificate_lockSession (certificate)) != CKR_OK) {
		goto cleanup;
	}
	session_locked = TRUE;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Performing signature"
	);

	if (
		(rv = pkcs11h_certificate_signAny (
			certificate,
			mech,
			from,
			flen,
			to,
			&tlen
		)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	rv = CKR_OK;

cleanup:

	if (session_locked) {
		pkcs11h_certificate_releaseSession (certificate);
		session_locked = FALSE;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_rsa_enc - return rv=%lu-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv == CKR_OK ? (int)tlen : -1;
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

	RSA_set_method (rsa, __openssl_methods.rsa);
	RSA_set_ex_data (rsa, __openssl_methods.rsa_index, openssl_session);
#if OPENSSL_VERSION_NUMBER < 0x10100001L
	rsa->flags |= RSA_FLAG_SIGN_VER;
#endif

#ifdef BROKEN_OPENSSL_ENGINE
	if (!rsa->engine) {
		rsa->engine = ENGINE_get_default_RSA ();
	}

	ENGINE_set_RSA(ENGINE_get_default_RSA (), &openssl_session->rsa);
	_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: OpenSSL engine support is broken! Workaround enabled");
#endif

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

static
pkcs11h_certificate_t
__pkcs11h_openssl_dsa_get_pkcs11h_certificate (
	IN DSA *dsa
) {
	pkcs11h_openssl_session_t session = NULL;

	_PKCS11H_ASSERT (dsa!=NULL);

	session = (pkcs11h_openssl_session_t)DSA_get_ex_data (dsa, __openssl_methods.dsa_index);

	_PKCS11H_ASSERT (session!=NULL);
	_PKCS11H_ASSERT (session->certificate!=NULL);

	return session->certificate;
}

static
DSA_SIG *
__pkcs11h_openssl_dsa_do_sign(
	IN const unsigned char *dgst,
	IN int dlen,
	OUT DSA *dsa
) {
	pkcs11h_certificate_t certificate = __pkcs11h_openssl_dsa_get_pkcs11h_certificate (dsa);
	unsigned char *sigbuf = NULL;
	size_t siglen;
	DSA_SIG *sig = NULL;
	DSA_SIG *ret = NULL;
	BIGNUM *r = NULL;
	BIGNUM *s = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_dsa_do_sign - entered dgst=%p, dlen=%d, dsa=%p",
		(void *)dgst,
		dlen,
		(void *)dsa
	);

	_PKCS11H_ASSERT (dgst!=NULL);
	_PKCS11H_ASSERT (dsa!=NULL);
	_PKCS11H_ASSERT (certificate!=NULL);

	if (
		(rv = pkcs11h_certificate_signAny (
			certificate,
			CKM_DSA,
			dgst,
			(size_t)dlen,
			NULL,
			&siglen
		)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((rv = _pkcs11h_mem_malloc ((void *)&sigbuf, siglen)) != CKR_OK) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot cannot allocate signature buffer");
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_signAny (
			certificate,
			CKM_DSA,
			dgst,
			(size_t)dlen,
			sigbuf,
			&siglen
		)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((sig = DSA_SIG_new ()) == NULL) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot allocate DSA_SIG");
		goto cleanup;
	}

	if ((r = BN_bin2bn (&sigbuf[0], siglen/2, NULL)) == NULL) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot convert dsa r");
		goto cleanup;
	}

	if ((s = BN_bin2bn (&sigbuf[siglen/2], siglen/2, NULL)) == NULL) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot convert dsa s");
		goto cleanup;
	}

	DSA_SIG_set0 (sig, r, s);
	ret = sig;
	sig = NULL;
	r = NULL;
	s = NULL;

cleanup:

	if (sigbuf != NULL) {
		_pkcs11h_mem_free ((void *)&sigbuf);
	}

	if (sig != NULL) {
		DSA_SIG_free (sig);
		sig = NULL;
	}

	if (r != NULL) {
		BN_clear_free (r);
	}

	if (s != NULL) {
		BN_clear_free (s);
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_dsa_do_sign - return sig=%p",
		(void *)sig
	);

	return ret;
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

	DSA_set_method (dsa, __openssl_methods.dsa);
	DSA_set_ex_data (dsa, __openssl_methods.dsa_index, openssl_session);

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

#ifdef __ENABLE_EC

static
pkcs11h_certificate_t
__pkcs11h_openssl_eckey_get_pkcs11h_certificate (
	IN EC_KEY *ec
) {
	pkcs11h_openssl_session_t session = NULL;

	_PKCS11H_ASSERT (ec!=NULL);

	session = (pkcs11h_openssl_session_t)EC_KEY_get_ex_data (ec, __openssl_methods.eckey_index);

	_PKCS11H_ASSERT (session!=NULL);
	_PKCS11H_ASSERT (session->certificate!=NULL);

	return session->certificate;
}

static
ECDSA_SIG *
__pkcs11h_openssl_eckey_do_sign(
	IN const unsigned char *dgst,
	IN int dlen,
	IN const BIGNUM *inv,
	IN const BIGNUM *r,
	OUT EC_KEY *ec
) {
	pkcs11h_certificate_t certificate = __pkcs11h_openssl_eckey_get_pkcs11h_certificate (ec);
	unsigned char *sigbuf = NULL;
	size_t siglen;
	ECDSA_SIG *sig = NULL;
	ECDSA_SIG *ret = NULL;
	BIGNUM *sig_r = NULL;
	BIGNUM *sig_s = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_eckey_do_sign - entered dgst=%p, dlen=%d, inv=%p, r=%p, ec=%p",
		(void *)dgst,
		dlen,
		(void *)inv,
		(void *)r,
		(void *)ec
	);

	_PKCS11H_ASSERT (dgst!=NULL);
	_PKCS11H_ASSERT (inv==NULL);
	_PKCS11H_ASSERT (r==NULL);
	_PKCS11H_ASSERT (ec!=NULL);
	_PKCS11H_ASSERT (certificate!=NULL);

	if (
		(rv = pkcs11h_certificate_signAny (
			certificate,
			CKM_ECDSA,
			dgst,
			(size_t)dlen,
			NULL,
			&siglen
		)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((rv = _pkcs11h_mem_malloc ((void *)&sigbuf, siglen)) != CKR_OK) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot cannot allocate signature buffer");
		goto cleanup;
	}

	if (
		(rv = pkcs11h_certificate_signAny (
			certificate,
			CKM_ECDSA,
			dgst,
			(size_t)dlen,
			sigbuf,
			&siglen
		)) != CKR_OK
	) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot perform signature %ld:'%s'", rv, pkcs11h_getMessage (rv));
		goto cleanup;
	}

	if ((sig = ECDSA_SIG_new ()) == NULL) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot allocate ECDSA_SIG");
		goto cleanup;
	}

	if ((sig_r = BN_bin2bn (&sigbuf[0], siglen/2, NULL)) == NULL) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot convert eckey r");
		goto cleanup;
	}

	if ((sig_s = BN_bin2bn (&sigbuf[siglen/2], siglen/2, NULL)) == NULL) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot convert eckey s");
		goto cleanup;
	}

	if (!ECDSA_SIG_set0(sig, sig_r, sig_s)) {
		_PKCS11H_LOG (PKCS11H_LOG_WARN, "PKCS#11: Cannot set eckey r, s");
		goto cleanup;
	}
	sig_r = NULL;
	sig_s = NULL;

	ret = sig;
	sig = NULL;

cleanup:

	if (sigbuf != NULL) {
		_pkcs11h_mem_free ((void *)&sigbuf);
	}

	if (sig != NULL) {
		ECDSA_SIG_free (sig);
		sig = NULL;
	}

	if (sig_r != NULL) {
		BN_free(sig_r);
		sig_r = NULL;
	}

	if (sig_s != NULL) {
		BN_free(sig_s);
		sig_s = NULL;
	}

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_openssl_eckey_do_sign - return sig=%p",
		(void *)sig
	);

	return ret;
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

	EC_KEY_set_method (ec, __openssl_methods.eckey);
	EC_KEY_set_ex_data (ec, __openssl_methods.eckey_index, openssl_session);

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

PKCS11H_BOOL
_pkcs11h_openssl_initialize (void) {

	PKCS11H_BOOL ret = FALSE;

	_PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_openssl_initialize - entered"
	);
#ifndef OPENSSL_NO_RSA
	if (__openssl_methods.rsa != NULL) {
		RSA_meth_free (__openssl_methods.rsa);
	}
	if ((__openssl_methods.rsa = RSA_meth_dup (RSA_get_default_method ())) == NULL) {
		goto cleanup;
	}
	RSA_meth_set1_name (__openssl_methods.rsa, "pkcs11h");
	RSA_meth_set_priv_dec (__openssl_methods.rsa, __pkcs11h_openssl_rsa_dec);
	RSA_meth_set_priv_enc (__openssl_methods.rsa, __pkcs11h_openssl_rsa_enc);
	RSA_meth_set_flags (__openssl_methods.rsa, RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY);
	__openssl_methods.rsa_index = RSA_get_ex_new_index (
		0,
		"pkcs11h",
		NULL,
		__pkcs11h_openssl_ex_data_dup,
		__pkcs11h_openssl_ex_data_free
	);
#endif
#ifndef OPENSSL_NO_DSA
	if (__openssl_methods.dsa != NULL) {
		DSA_meth_free (__openssl_methods.dsa);
	}
	__openssl_methods.dsa = DSA_meth_dup (DSA_get_default_method ());
	DSA_meth_set1_name (__openssl_methods.dsa, "pkcs11h");
	DSA_meth_set_sign (__openssl_methods.dsa, __pkcs11h_openssl_dsa_do_sign);
	__openssl_methods.dsa_index = DSA_get_ex_new_index (
		0,
		"pkcs11h",
		NULL,
		__pkcs11h_openssl_ex_data_dup,
		__pkcs11h_openssl_ex_data_free
	);
#endif
#ifdef __ENABLE_EC
	if (__openssl_methods.eckey != NULL) {
		EC_KEY_METHOD_free(__openssl_methods.eckey);
	}
	__openssl_methods.eckey = EC_KEY_METHOD_new (EC_KEY_get_default_method ());
	{
		int (*sig)(
			int type,
			const unsigned char *dgst,
			int dlen,
			unsigned char *sig,
			unsigned int *siglen,
			const BIGNUM *kinv,
			const BIGNUM *r,
			EC_KEY *eckey
		) = NULL;

		EC_KEY_METHOD_get_sign(__openssl_methods.eckey, &sig, NULL, NULL);
		EC_KEY_METHOD_set_sign(__openssl_methods.eckey, sig, NULL, __pkcs11h_openssl_eckey_do_sign);
	}
	__openssl_methods.eckey_index = EC_KEY_get_ex_new_index (
		0,
		"pkcs11h",
		NULL,
		__pkcs11h_openssl_ex_data_dup,
		__pkcs11h_openssl_ex_data_free
	);
#endif
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
#ifndef OPENSSL_NO_RSA
	if (__openssl_methods.rsa != NULL) {
		RSA_meth_free (__openssl_methods.rsa);
		__openssl_methods.rsa = NULL;
	}
#endif
#ifndef OPENSSL_NO_DSA
	if (__openssl_methods.dsa != NULL) {
		DSA_meth_free (__openssl_methods.dsa);
		__openssl_methods.dsa = NULL;
	}
#endif
#ifdef __ENABLE_EC
	if (__openssl_methods.eckey != NULL) {
		EC_KEY_METHOD_free(__openssl_methods.eckey);
		__openssl_methods.eckey = NULL;
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
	__pkcs11_openssl_d2i_t d2i1 = NULL;

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

	d2i1 = (__pkcs11_openssl_d2i_t)certificate_blob;
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

#if OPENSSL_VERSION_NUMBER <0x10100000L
	OpenSSL_add_all_digests ();
#endif

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
#ifndef OPENSSL_NO_RSA
	else if (EVP_PKEY_id (evp) == EVP_PKEY_DSA) {
		if (!__pkcs11h_openssl_session_setDSA(openssl_session, evp)) {
			goto cleanup;
		}
	}
#endif
#ifdef __ENABLE_EC
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

