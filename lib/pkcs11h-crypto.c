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

#include <pkcs11-helper-1.0/pkcs11h-core.h>
#include "_pkcs11h-util.h"
#include "_pkcs11h-sys.h"
#include "_pkcs11h-crypto.h"

#if defined(ENABLE_PKCS11H_ENGINE_OPENSSL)
#include <openssl/x509.h>
#endif

#if defined(ENABLE_PKCS11H_ENGINE_GNUTLS)
#include <gnutls/x509.h>
#endif

#if defined(ENABLE_PKCS11H_ENGINE_WIN32)
#include <wincrypt.h>
#if !defined(X509_MULTI_BYTE_INTEGER)
#define X509_MULTI_BYTE_INTEGER	((LPCSTR)28)
#endif
#if !defined(CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT)
#define CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT	0x02
#endif
#if !defined(CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT)
#define CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT	0x02
#endif

#endif

/*===========================================
 * Constants
 */

#if defined(ENABLE_PKCS11H_ENGINE_OPENSSL)

#if OPENSSL_VERSION_NUMBER < 0x00907000L && defined(CRYPTO_LOCK_ENGINE)
# define RSA_get_default_method RSA_get_default_openssl_method
#else
# ifdef HAVE_ENGINE_GET_DEFAULT_RSA
#  include <openssl/engine.h>
#  if OPENSSL_VERSION_NUMBER < 0x0090704fL
#   define BROKEN_OPENSSL_ENGINE
#  endif
# endif
#endif

#if OPENSSL_VERSION_NUMBER < 0x00907000L
#if !defined(RSA_PKCS1_PADDING_SIZE)
#define RSA_PKCS1_PADDING_SIZE 11
#endif
#endif

#endif

#if defined(ENABLE_PKCS11H_ENGINE_OPENSSL)

#if OPENSSL_VERSION_NUMBER < 0x00908000L
typedef unsigned char *pkcs11_openssl_d2i_t;
#else
typedef const unsigned char *pkcs11_openssl_d2i_t;
#endif

#endif

#if defined(ENABLE_PKCS11H_ENGINE_OPENSSL)

static
int
__pkcs11h_crypto_openssl_initialize (
	IN void * const global_data
);

static
int
__pkcs11h_crypto_openssl_uninitialize (
	IN void * const global_data
);

static
int
__pkcs11h_crypto_openssl_certificate_get_expiration (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT time_t * const expiration
);

static
int
__pkcs11h_crypto_openssl_certificate_get_dn (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const dn,
	IN const size_t dn_max
);

static
int
__pkcs11h_crypto_openssl_certificate_get_serial (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const serial,
	IN const size_t serial_max
);

static
int
__pkcs11h_crypto_openssl_certificate_is_issuer (
	IN void * const global_data,
	IN const unsigned char * const signer_blob,
	IN const size_t signer_blob_size,
	IN const unsigned char * const cert_blob,
	IN const size_t cert_blob_size
);

#endif

#if defined(ENABLE_PKCS11H_ENGINE_GNUTLS)

static
int
__pkcs11h_crypto_gnutls_initialize (
	IN void * const global_data
);

static
int
__pkcs11h_crypto_gnutls_uninitialize (
	IN void * const global_data
);

static
int
__pkcs11h_crypto_gnutls_certificate_get_expiration (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT time_t * const expiration
);

static
int
__pkcs11h_crypto_gnutls_certificate_get_dn (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const dn,
	IN const size_t dn_max
);

static
int
__pkcs11h_crypto_gnutls_certificate_get_serial (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const serial,
	IN const size_t serial_max
);

static
int
__pkcs11h_crypto_gnutls_certificate_is_issuer (
	IN void * const global_data,
	IN const unsigned char * const signer_blob,
	IN const size_t signer_blob_size,
	IN const unsigned char * const cert_blob,
	IN const size_t cert_blob_size
);

#endif

#if defined(ENABLE_PKCS11H_ENGINE_WIN32)

typedef PCCERT_CONTEXT (WINAPI *CertCreateCertificateContext_t) (
	DWORD dwCertEncodingType,
	const BYTE *pbCertEncoded,
	DWORD cbCertEncoded
);
typedef BOOL (WINAPI *CertFreeCertificateContext_t) (
	PCCERT_CONTEXT pCertContext
);
typedef DWORD (WINAPI *CertNameToStrW_t) (
	DWORD dwCertEncodingType,
	PCERT_NAME_BLOB pName,
	DWORD dwStrType,
	LPWSTR psz,
	DWORD csz
);
typedef BOOL (WINAPI *CryptDecodeObject_t) (
	DWORD dwCertEncodingType,
	LPCSTR lpszStructType,
	const BYTE* pbEncoded,
	DWORD cbEncoded,
	DWORD dwFlags,
	void* pvStructInfo,
	DWORD* pcbStructInfo
);
typedef BOOL (WINAPI *CryptVerifyCertificateSignatureEx_t) (
	void *hCryptProv,
	DWORD dwCertEncodingType,
	DWORD dwSubjectType,
	void* pvSubject,
	DWORD dwIssuerType,
	void* pvIssuer,
	DWORD dwFlags,
	void* pvReserved
);

typedef struct __crypto_win32_data_s {
	HMODULE handle;
	CertCreateCertificateContext_t p_CertCreateCertificateContext;
	CertFreeCertificateContext_t p_CertFreeCertificateContext;
	CertNameToStrW_t p_CertNameToStrW;
	CryptDecodeObject_t p_CryptDecodeObject;
	CryptVerifyCertificateSignatureEx_t p_CryptVerifyCertificateSignatureEx;
} *__crypto_win32_data_t;

static
int
__pkcs11h_crypto_win32_initialize (
	IN void * const global_data
);

static
int
__pkcs11h_crypto_win32_uninitialize (
	IN void * const global_data
);

static
int
__pkcs11h_crypto_win32_certificate_get_expiration (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT time_t * const expiration
);

static
int
__pkcs11h_crypto_win32_certificate_get_dn (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const dn,
	IN const size_t dn_max
);

static
int
__pkcs11h_crypto_win32_certificate_get_serial (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const serial,
	IN const size_t serial_max
);

static
int
__pkcs11h_crypto_win32_certificate_is_issuer (
	IN void * const global_data,
	IN const unsigned char * const signer_blob,
	IN const size_t signer_blob_size,
	IN const unsigned char * const cert_blob,
	IN const size_t cert_blob_size
);

#endif

#if defined(ENABLE_PKCS11H_ENGINE_OPENSSL)
pkcs11h_engine_crypto_t g_pkcs11h_crypto_engine = {
	NULL,
	__pkcs11h_crypto_openssl_initialize,
	__pkcs11h_crypto_openssl_uninitialize,
	__pkcs11h_crypto_openssl_certificate_get_expiration,
	__pkcs11h_crypto_openssl_certificate_get_dn,
	__pkcs11h_crypto_openssl_certificate_get_serial,
	__pkcs11h_crypto_openssl_certificate_is_issuer
};
#elif defined(ENABLE_PKCS11H_ENGINE_GNUTLS)
pkcs11h_engine_crypto_t g_pkcs11h_crypto_engine = {
	NULL,
	__pkcs11h_crypto_gnutls_initialize,
	__pkcs11h_crypto_gnutls_uninitialize,
	__pkcs11h_crypto_gnutls_certificate_get_expiration,
	__pkcs11h_crypto_gnutls_certificate_get_dn,
	__pkcs11h_crypto_gnutls_certificate_get_serial,
	__pkcs11h_crypto_gnutls_certificate_is_issuer
};
#elif defined(ENABLE_PKCS11H_ENGINE_WIN32)
static struct __crypto_win32_data_s s_win32_data;
pkcs11h_engine_crypto_t g_pkcs11h_crypto_engine = {
	&s_win32_data,
	__pkcs11h_crypto_win32_initialize,
	__pkcs11h_crypto_win32_uninitialize,
	__pkcs11h_crypto_win32_certificate_get_expiration,
	__pkcs11h_crypto_win32_certificate_get_dn,
	__pkcs11h_crypto_win32_certificate_get_serial,
	__pkcs11h_crypto_win32_certificate_is_issuer
};
#else
pkcs11h_engine_crypto_t g_pkcs11h_crypto_engine = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif

CK_RV
pkcs11h_engine_setCrypto (
	IN const pkcs11h_engine_crypto_t * const engine
) {
	PKCS11H_ASSERT (engine!=NULL);

	memmove (&g_pkcs11h_crypto_engine, engine, sizeof (pkcs11h_engine_crypto_t));

	return CKR_OK;
}

#if defined(ENABLE_PKCS11H_ENGINE_OPENSSL)

static
int
__pkcs11h_crypto_openssl_initialize (
	IN void * const global_data
) {
	(void)global_data;

	OpenSSL_add_all_digests ();

	return TRUE;
}

static
int
__pkcs11h_crypto_openssl_uninitialize (
	IN void * const global_data
) {
	(void)global_data;

	return TRUE;
}

static
int
__pkcs11h_crypto_openssl_certificate_get_expiration (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT time_t * const expiration
) {
	X509 *x509 = NULL;

	(void)global_data;

	/*PKCS11H_ASSERT (global_data!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (blob!=NULL);
	PKCS11H_ASSERT (expiration!=NULL);

	*expiration = (time_t)0;

	x509 = X509_new ();

	if (x509 != NULL) {
		pkcs11_openssl_d2i_t d2i = (pkcs11_openssl_d2i_t)blob;

		if (
			d2i_X509 (&x509, &d2i, blob_size)
		) {
			ASN1_TIME *notBefore = X509_get_notBefore (x509);
			ASN1_TIME *notAfter = X509_get_notAfter (x509);

			if (
				notBefore != NULL &&
				notAfter != NULL &&
				X509_cmp_current_time (notBefore) <= 0 &&
				X509_cmp_current_time (notAfter) >= 0 &&
				notAfter->length >= 12
			) {
				struct tm tm1;
				time_t now = time (NULL);

				memset (&tm1, 0, sizeof (tm1));
				tm1.tm_year = (notAfter->data[ 0] - '0') * 10 + (notAfter->data[ 1] - '0') + 100;
				tm1.tm_mon  = (notAfter->data[ 2] - '0') * 10 + (notAfter->data[ 3] - '0') - 1;
				tm1.tm_mday = (notAfter->data[ 4] - '0') * 10 + (notAfter->data[ 5] - '0');
				tm1.tm_hour = (notAfter->data[ 6] - '0') * 10 + (notAfter->data[ 7] - '0');
				tm1.tm_min  = (notAfter->data[ 8] - '0') * 10 + (notAfter->data[ 9] - '0');
				tm1.tm_sec  = (notAfter->data[10] - '0') * 10 + (notAfter->data[11] - '0');

				tm1.tm_sec += (int)(mktime (localtime (&now)) - mktime (gmtime (&now)));

				*expiration = mktime (&tm1);
			}
		}

		X509_free (x509);
		x509 = NULL;
	}

	return *expiration != (time_t)0;
}

static
int
__pkcs11h_crypto_openssl_certificate_get_dn (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const dn,
	IN const size_t dn_max
) {
	X509 *x509 = NULL;
	pkcs11_openssl_d2i_t d2i1;

	(void)global_data;

	/*PKCS11H_ASSERT (global_data!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (blob!=NULL);
	PKCS11H_ASSERT (dn!=NULL);
	PKCS11H_ASSERT (dn_max>0);

	dn[0] = '\x0';

	if (blob_size > 0) {
		if ((x509 = X509_new ()) != NULL) {
			d2i1 = (pkcs11_openssl_d2i_t)blob;
			if (d2i_X509 (&x509, &d2i1, blob_size)) {
				X509_NAME_oneline (
					X509_get_subject_name (x509),
					dn,
					dn_max
				);
			}

			X509_free (x509);
			x509 = NULL;
		}
	}

	return dn[0] != '\x0';
}

static
int
__pkcs11h_crypto_openssl_certificate_get_serial (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const serial,
	IN const size_t serial_max
) {
	X509 *x509 = NULL;
	BIO *bioSerial = NULL;

	(void)global_data;

	/*PKCS11H_ASSERT (global_data!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (blob!=NULL);
	PKCS11H_ASSERT (serial!=NULL);
	PKCS11H_ASSERT (serial_max>0);

	serial[0] = '\x0';

	if ((x509 = X509_new ()) != NULL) {
		pkcs11_openssl_d2i_t d2i1 = (pkcs11_openssl_d2i_t)blob;
		if (d2i_X509 (&x509, &d2i1, blob_size)) {
			if ((bioSerial = BIO_new (BIO_s_mem ())) != NULL) {
				int n;

				i2a_ASN1_INTEGER(bioSerial, X509_get_serialNumber (x509));
				n = BIO_read (bioSerial, serial, serial_max-1);
				if (n<0) {
					serial[0] = '\0';
				}
				else {
					serial[n] = '\0';
				}

				BIO_free_all (bioSerial);
				bioSerial = NULL;
			}
		}

		X509_free (x509);
		x509 = NULL;
	}

	return serial[0] != '\x0';
}

static
int
__pkcs11h_crypto_openssl_certificate_is_issuer (
	IN void * const global_data,
	IN const unsigned char * const issuer_blob,
	IN const size_t issuer_blob_size,
	IN const unsigned char * const cert_blob,
	IN const size_t cert_blob_size
) {
	X509 *x509_issuer = NULL;
	X509 *x509_cert = NULL;
	EVP_PKEY *pub_issuer = NULL;
	pkcs11_openssl_d2i_t d2i;
	PKCS11H_BOOL is_issuer = FALSE;
	PKCS11H_BOOL ok = TRUE;

	(void)global_data;

	/*PKCS11H_ASSERT (global_data!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (issuer_blob!=NULL);
	PKCS11H_ASSERT (cert_blob!=NULL);

	if (
		ok &&
		(x509_issuer = X509_new ()) == NULL
	) {
		ok = FALSE;
	}

	if (
		ok &&
		(x509_cert = X509_new ()) == NULL
	) {
		ok = FALSE;
	}

	if (ok && (x509_issuer == NULL || x509_cert == NULL)) {
		ok = FALSE;
	}

	d2i = (pkcs11_openssl_d2i_t)issuer_blob;
	if (
		ok &&
		!d2i_X509 (
			&x509_issuer,
			&d2i,
			issuer_blob_size
		)
	) {
		ok = FALSE;
	}

	d2i = (pkcs11_openssl_d2i_t)cert_blob;
	if (
		ok &&
		!d2i_X509 (
			&x509_cert,
			&d2i,
			cert_blob_size
		)
	) {
		ok = FALSE;
	}

	if (
		ok &&
		(pub_issuer = X509_get_pubkey (x509_issuer)) == NULL
	) {
		ok = FALSE;
	}

	if (
		ok &&
		!X509_NAME_cmp (
			X509_get_subject_name (x509_issuer),
			X509_get_issuer_name (x509_cert)
		) &&
		X509_verify (x509_cert, pub_issuer) == 1
	) {
		is_issuer = TRUE;
	}

	if (pub_issuer != NULL) {
		EVP_PKEY_free (pub_issuer);
		pub_issuer = NULL;
	}
	if (x509_issuer != NULL) {
		X509_free (x509_issuer);
		x509_issuer = NULL;
	}
	if (x509_cert != NULL) {
		X509_free (x509_cert);
		x509_cert = NULL;
	}

	return is_issuer;
}

/*======================================================================*
 * FIXUPS
 *======================================================================*/

#ifdef BROKEN_OPENSSL_ENGINE
static void broken_openssl_init(void) __attribute__ ((constructor));
static void  broken_openssl_init(void)
{
	SSL_library_init();
	ENGINE_load_openssl();
	ENGINE_register_all_RSA();
}
#endif

#endif				/* ENABLE_PKCS11H_ENGINE_OPENSSL */

#if defined(ENABLE_PKCS11H_ENGINE_GNUTLS)

static
int
__pkcs11h_crypto_gnutls_initialize (
	IN void * const global_data
) {
	(void)global_data;

	/*PKCS11H_ASSERT (global_data!=NULL); NOT NEEDED*/
	if (gnutls_global_init () != GNUTLS_E_SUCCESS) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}

static
int
__pkcs11h_crypto_gnutls_uninitialize (
	IN void * const global_data
) {
	(void)global_data;

	/*PKCS11H_ASSERT (global_data!=NULL); NOT NEEDED*/
	gnutls_global_deinit ();

	return TRUE;
}

static
int
__pkcs11h_crypto_gnutls_certificate_get_expiration (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT time_t * const expiration
) {
	gnutls_x509_crt_t cert = NULL;

	(void)global_data;

	/*PKCS11H_ASSERT (global_data!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (blob!=NULL);
	PKCS11H_ASSERT (expiration!=NULL);

	*expiration = (time_t)0;

	if (gnutls_x509_crt_init (&cert) == GNUTLS_E_SUCCESS) {
		gnutls_datum_t datum = {(unsigned char *)blob, blob_size};

		if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {

			time_t activation_time = gnutls_x509_crt_get_activation_time (cert);
			time_t expiration_time = gnutls_x509_crt_get_expiration_time (cert);
			time_t now = time (NULL);

			if (
				now >= activation_time &&
				now <= expiration_time
			) {
				*expiration = expiration_time;
			}
		}
		gnutls_x509_crt_deinit (cert);
	}

	return *expiration != (time_t)0;
}

static
int
__pkcs11h_crypto_gnutls_certificate_get_dn (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const dn,
	IN const size_t dn_max
) {
	gnutls_x509_crt_t cert = NULL;

	(void)global_data;

	/*PKCS11H_ASSERT (global_data!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (blob!=NULL);
	PKCS11H_ASSERT (dn!=NULL);
	PKCS11H_ASSERT (dn_max>0);

	dn[0] = '\x0';

	if (gnutls_x509_crt_init (&cert) == GNUTLS_E_SUCCESS) {
		gnutls_datum_t datum = {(unsigned char *)blob, blob_size};

		if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {
			size_t s = dn_max;
			if (
				gnutls_x509_crt_get_dn (
					cert,
					dn,
					&s
				) != GNUTLS_E_SUCCESS
			) {
				/* gnutls sets output parameters */
				dn[0] = '\x0';
			}
		}
		gnutls_x509_crt_deinit (cert);
	}

	return dn[0] != '\x0';
}

static
int
__pkcs11h_crypto_gnutls_certificate_get_serial (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const serial,
	IN const size_t serial_max
) {
	gnutls_x509_crt_t cert = NULL;

	(void)global_data;

	/*PKCS11H_ASSERT (global_data!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (blob!=NULL);
	PKCS11H_ASSERT (serial!=NULL);
	PKCS11H_ASSERT (serial_max>0);

	serial[0] = '\x0';

	if (gnutls_x509_crt_init (&cert) == GNUTLS_E_SUCCESS) {
		gnutls_datum_t datum = {(unsigned char *)blob, blob_size};

		if (gnutls_x509_crt_import (cert, &datum, GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS) {
			unsigned char ser[1024];
			size_t ser_size = sizeof (ser);
			if (gnutls_x509_crt_get_serial (cert, ser, &ser_size) == GNUTLS_E_SUCCESS) {
				_pkcs11h_util_binaryToHex (
					serial,
					serial_max,
					ser,
					ser_size
				);
			}
		}
		gnutls_x509_crt_deinit (cert);
	}

	return serial[0] != '\x0';
}

static
int
__pkcs11h_crypto_gnutls_certificate_is_issuer (
	IN void * const global_data,
	IN const unsigned char * const issuer_blob,
	IN const size_t issuer_blob_size,
	IN const unsigned char * const cert_blob,
	IN const size_t cert_blob_size
) {
	gnutls_x509_crt_t cert_issuer = NULL;
	gnutls_x509_crt_t cert_cert = NULL;
	gnutls_datum_t datum;
	PKCS11H_BOOL is_issuer = FALSE;
	PKCS11H_BOOL ok = TRUE;
	unsigned int result = 0;

	(void)global_data;

	/*PKCS11H_ASSERT (global_data!=NULL); NOT NEEDED*/
	PKCS11H_ASSERT (issuer_blob!=NULL);
	PKCS11H_ASSERT (cert_blob!=NULL);

	if (ok && gnutls_x509_crt_init (&cert_issuer) != GNUTLS_E_SUCCESS) {
		/* gnutls sets output */
		cert_issuer = NULL;
		ok = FALSE;
	}
	if (ok && gnutls_x509_crt_init (&cert_cert) != GNUTLS_E_SUCCESS) {
		/* gnutls sets output */
		cert_cert = NULL;
		ok = FALSE;
	}

	datum.data = (unsigned char *)issuer_blob;
	datum.size = issuer_blob_size;

	if (
		ok &&
		gnutls_x509_crt_import (
			cert_issuer,
			&datum,
			GNUTLS_X509_FMT_DER
		) != GNUTLS_E_SUCCESS
	) {
		ok = FALSE;
	}

	datum.data = (unsigned char *)cert_blob;
	datum.size = cert_blob_size;

	if (
		ok &&
		gnutls_x509_crt_import (
			cert_cert,
			&datum,
			GNUTLS_X509_FMT_DER
		) != GNUTLS_E_SUCCESS
	) {
		ok = FALSE;
	}

	if (
		ok &&
		gnutls_x509_crt_verify (
			cert_cert,
			&cert_issuer,
			1,
			0,
			&result
		) &&
		(result & GNUTLS_CERT_INVALID) == 0
	) {
		is_issuer = TRUE;
	}

	if (cert_cert != NULL) {
		gnutls_x509_crt_deinit (cert_cert);
		cert_cert = NULL;
	}

	if (cert_issuer != NULL) {
		gnutls_x509_crt_deinit (cert_issuer);
		cert_issuer = NULL;
	}

	return is_issuer;
}

#endif				/* ENABLE_PKCS11H_ENGINE_GNUTLS */

#if defined(ENABLE_PKCS11H_ENGINE_WIN32)

static
int
__pkcs11h_crypto_win32_initialize (
	IN void * const global_data
) {
	__crypto_win32_data_t data = (__crypto_win32_data_t)global_data;

	PKCS11H_ASSERT (global_data!=NULL);

	memset (data, 0, sizeof (struct __crypto_win32_data_s));

	data->handle = LoadLibraryA ("crypt32.dll");
	if (data->handle == NULL) {
		return 0;
	}

	data->p_CertCreateCertificateContext = (CertCreateCertificateContext_t)GetProcAddress (
		data->handle,
		"CertCreateCertificateContext"
	);
	data->p_CertFreeCertificateContext = (CertFreeCertificateContext_t)GetProcAddress (
		data->handle,
		"CertFreeCertificateContext"
	);
	data->p_CertNameToStrW = (CertNameToStrW_t)GetProcAddress (
		data->handle,
		"CertNameToStrW"
	);
	data->p_CryptDecodeObject = (CryptDecodeObject_t)GetProcAddress (
		data->handle,
		"CryptDecodeObject"
	);
	data->p_CryptVerifyCertificateSignatureEx = (CryptVerifyCertificateSignatureEx_t)GetProcAddress (
		data->handle,
		"CryptVerifyCertificateSignatureEx"
	);

	if (
		data->p_CertCreateCertificateContext == NULL ||
		data->p_CertFreeCertificateContext == NULL ||
		data->p_CertNameToStrW == NULL ||
		data->p_CryptDecodeObject == NULL ||
		data->p_CryptVerifyCertificateSignatureEx == NULL
	) {
		FreeLibrary (data->handle);
		data->handle = NULL;
		return 0;
	}

	return 1;
}

static
int
__pkcs11h_crypto_win32_uninitialize (
	IN void * const global_data
) {
	__crypto_win32_data_t data = (__crypto_win32_data_t)global_data;

	PKCS11H_ASSERT (global_data!=NULL);

	if (data->handle != NULL) {
		FreeLibrary (data->handle);
		data->handle = NULL;
	}

	return 1;
}

static
int
__pkcs11h_crypto_win32_certificate_get_expiration (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT time_t * const expiration
) {
	__crypto_win32_data_t data = (__crypto_win32_data_t)global_data;
	PCCERT_CONTEXT cert = NULL;
	PKCS11H_BOOL ok = TRUE;
	SYSTEMTIME st;

	PKCS11H_ASSERT (global_data!=NULL);
	PKCS11H_ASSERT (blob!=NULL);
	PKCS11H_ASSERT (expiration!=NULL);

	*expiration = (time_t)0;

	if (
		ok &&
		(cert = data->p_CertCreateCertificateContext (
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
			blob,
			blob_size
		)) == NULL
	) {
		ok = FALSE;
	}

	if (
		ok &&
		!FileTimeToSystemTime (
			&cert->pCertInfo->NotAfter,
			&st
		)
	) {
		ok = FALSE;
	}

	if (ok) {
		struct tm tm1;
		time_t now = time (NULL);

		memset (&tm1, 0, sizeof (tm1));
		tm1.tm_year = st.wYear - 1900;
		tm1.tm_mon  = st.wMonth - 1;
		tm1.tm_mday = st.wDay;
		tm1.tm_hour = st.wHour;
		tm1.tm_min  = st.wMinute;
		tm1.tm_sec  = st.wSecond;

		tm1.tm_sec += (int)(mktime (localtime (&now)) - mktime (gmtime (&now)));

		*expiration = mktime (&tm1);
	}

	if (cert != NULL) {
		data->p_CertFreeCertificateContext (cert);
		cert = NULL;
	}

	return ok != FALSE;
}

static
int
__pkcs11h_crypto_win32_certificate_get_dn (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const dn,
	IN const size_t dn_max
) {
	__crypto_win32_data_t data = (__crypto_win32_data_t)global_data;
	PCCERT_CONTEXT cert = NULL;
	PKCS11H_BOOL ok = TRUE;
	DWORD wsize;
	WCHAR *wstr = NULL;

	PKCS11H_ASSERT (global_data!=NULL);
	PKCS11H_ASSERT (blob!=NULL);
	PKCS11H_ASSERT (dn!=NULL);
	PKCS11H_ASSERT (dn_max>0);

	dn[0] = '\x0';

	if (
		ok &&
		(cert = data->p_CertCreateCertificateContext (
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
			blob,
			blob_size
		)) == NULL
	) {
		ok = FALSE;
	}

	if (
		ok &&
		(wsize = data->p_CertNameToStrW (
			X509_ASN_ENCODING,
			&cert->pCertInfo->Subject,
			CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
			NULL,
			0
		)) == 0
	) {
		ok = FALSE;
	}
	
	if (
		ok &&
		(wstr = (WCHAR *)g_pkcs11h_sys_engine.malloc (wsize * sizeof (WCHAR))) == NULL
	) {
		ok = FALSE;
	}
			
	if (
		ok &&
		(wsize = data->p_CertNameToStrW (
			X509_ASN_ENCODING,
			&cert->pCertInfo->Subject,
			CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
			wstr,
			wsize
		)) == 0
	) {
		ok = FALSE;
	}

	if (
		ok &&
		WideCharToMultiByte (
			CP_UTF8,
			0,
			wstr,
			-1,
			dn,
			dn_max,
			NULL,
			NULL
		) == 0
	) {
		ok = FALSE;
	}

	if (wstr != NULL) {
		g_pkcs11h_sys_engine.free (wstr);
		wstr = NULL;
	}

	if (cert != NULL) {
		data->p_CertFreeCertificateContext (cert);
		cert = NULL;
	}

	return ok != FALSE;
}

static
int
__pkcs11h_crypto_win32_certificate_get_serial (
	IN void * const global_data,
	IN const unsigned char * const blob,
	IN const size_t blob_size,
	OUT char * const serial,
	IN const size_t serial_max
) {
	__crypto_win32_data_t data = (__crypto_win32_data_t)global_data;
	PCCERT_CONTEXT cert = NULL;
	PKCS11H_BOOL ok = TRUE;
	PBYTE bin_serial = NULL;
	size_t i;

	PKCS11H_ASSERT (global_data!=NULL);
	PKCS11H_ASSERT (blob!=NULL);
	PKCS11H_ASSERT (serial!=NULL);
	PKCS11H_ASSERT (serial_max>0);

	serial[0] = '\x0';

	if (
		ok &&
		(cert = data->p_CertCreateCertificateContext (
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
			blob,
			blob_size
		)) == NULL
	) {
		ok = FALSE;
	}

	if (
		ok &&
		(bin_serial = (PBYTE)g_pkcs11h_sys_engine.malloc (cert->pCertInfo->SerialNumber.cbData)) == NULL
	) {
		ok = FALSE;
	}

	for (i=0;ok && i<cert->pCertInfo->SerialNumber.cbData;i++) {
		bin_serial[cert->pCertInfo->SerialNumber.cbData-1-i] = cert->pCertInfo->SerialNumber.pbData[i];
	}

	if (
		ok &&
		_pkcs11h_util_binaryToHex (
			serial,
			serial_max,
			bin_serial,
			cert->pCertInfo->SerialNumber.cbData
		) != CKR_OK
	) {
		ok = FALSE;
	}

	if (bin_serial != NULL) {
		g_pkcs11h_sys_engine.free (bin_serial);
		bin_serial = NULL;
	}

	if (cert != NULL) {
		data->p_CertFreeCertificateContext (cert);
		cert = NULL;
	}

	return ok != FALSE;
}

static
int
__pkcs11h_crypto_win32_certificate_is_issuer (
	IN void * const global_data,
	IN const unsigned char * const issuer_blob,
	IN const size_t issuer_blob_size,
	IN const unsigned char * const cert_blob,
	IN const size_t cert_blob_size
) {
	__crypto_win32_data_t data = (__crypto_win32_data_t)global_data;
	PCCERT_CONTEXT cert_issuer = NULL;
	PCCERT_CONTEXT cert_cert = NULL;
	PKCS11H_BOOL ok = TRUE;
	PKCS11H_BOOL issuer = FALSE;

	PKCS11H_ASSERT (global_data!=NULL);
	PKCS11H_ASSERT (issuer_blob!=NULL);
	PKCS11H_ASSERT (cert_blob!=NULL);

	if (
		ok &&
		(cert_issuer = data->p_CertCreateCertificateContext (
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
			issuer_blob,
			issuer_blob_size
		)) == NULL
	) {
		ok = FALSE;
	}

	if (
		ok &&
		(cert_cert = data->p_CertCreateCertificateContext (
			PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
			cert_blob,
			cert_blob_size
		)) == NULL
	) {
		ok = FALSE;
	}

	if (
		ok &&
		data->p_CryptVerifyCertificateSignatureEx (
			NULL,
			X509_ASN_ENCODING,
			CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT,
			(void *)cert_cert,
			CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT,
			(void *)cert_issuer,
			0,
			NULL
		)
	) {
		issuer = TRUE;
	}

	if (cert_issuer != NULL) {
		data->p_CertFreeCertificateContext (cert_issuer);
		cert_issuer = NULL;
	}

	if (cert_cert != NULL) {
		data->p_CertFreeCertificateContext (cert_cert);
		cert_cert = NULL;
	}

	return issuer != FALSE;
}

#endif				/* ENABLE_PKCS11H_ENGINE_WIN32 */
