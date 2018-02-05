#include "../../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <conio.h>
#else
#include <unistd.h>
#endif

#if !(defined(ENABLE_PKCS11H_OPENSSL) && defined(ENABLE_PKCS11H_CERTIFICATE))
int main () {
	printf ("!win32, openssl, certificate should be enabled for this test");
	exit (0);
	return 0;
}
#else

#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#include <pkcs11-helper-1.0/pkcs11h-openssl.h>
#include <unistd.h>

static
void
fatal0(const char * const m) {
	fprintf (stderr, "%s\n", m);
	exit (1);
}

static
void
fatal (const char * const m, CK_RV rv) {
	fprintf (stderr, "%s - %lu - %s\n", m, rv, pkcs11h_getMessage (rv));
	exit (1);
}

static
void
mypause (const char * const m) {
	char temp[10];

	fprintf (stdout, "%s", m);
	fflush (stdout);
	if (fgets (temp, sizeof (temp), stdin) == NULL) {
		fatal0("fgets failed");
	}
}

static
void
_pkcs11h_hooks_log (
	IN void * const global_data,
	IN unsigned flags,
	IN const char * const format,
	IN va_list args
) {
	vfprintf (stdout, format, args);
	fprintf (stdout, "\n");
	fflush (stdout);
}

static
PKCS11H_BOOL
_pkcs11h_hooks_token_prompt (
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry
) {
	char buf[1024];
	PKCS11H_BOOL fValidInput = FALSE;
	PKCS11H_BOOL fRet = FALSE;

	while (!fValidInput) {
		fprintf (stderr, "Please insert token '%s' 'ok' or 'cancel': ", token->display);
		if (fgets (buf, sizeof (buf), stdin) == NULL) {
			fatal0("fgets failed");
		}
		buf[sizeof (buf)-1] = '\0';
		fflush (stdin);

		if (buf[strlen (buf)-1] == '\n') {
			buf[strlen (buf)-1] = '\0';
		}
		if (buf[strlen (buf)-1] == '\r') {
			buf[strlen (buf)-1] = '\0';
		}

		if (!strcmp (buf, "ok")) {
			fValidInput = TRUE;
			fRet = TRUE;
		}
		else if (!strcmp (buf, "cancel")) {
			fValidInput = TRUE;
		}
	}

	return fRet;
}

static
PKCS11H_BOOL
_pkcs11h_hooks_pin_prompt (
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const pin,
	IN const size_t pin_max
) {
	char prompt[1024];
	char *p = NULL;

	snprintf (prompt, sizeof (prompt), "Please enter '%s' PIN or 'cancel': ", token->display);

#if defined(_WIN32)
	{
		size_t i = 0;
		char c;
		while (i < pin_max && (c = getch ()) != '\r') {
			pin[i++] = c;
		}
	}

	fprintf (stderr, "\n");
#else
	p = getpass (prompt);
#endif

	strncpy (pin, p, pin_max);
	pin[pin_max-1] = '\0';

	return strcmp (pin, "cancel") != 0;
}

void
sign_test (const pkcs11h_openssl_session_t session) {

	unsigned char *blob;
	size_t blob_size;

	EVP_PKEY *evp;
	X509 *x509;
	EVP_MD_CTX* ctx;

	if ((x509 = pkcs11h_openssl_session_getX509(session)) == NULL) {
		fatal0("pkcs11h_openssl_session_getX509 failed");
	}

	if ((evp = pkcs11h_openssl_session_getEVP(session)) == NULL) {
		fatal0("pkcs11h_openssl_session_getEVP failed");
	}

	if ((ctx = EVP_MD_CTX_create()) == NULL) {
		fatal0("EVP_MD_CTX_create failed");
	}

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == -1) {
		fatal0("EVP_DigestInit_ex failed");
	}

	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, evp) == -1) {
		fatal0("EVP_DigestSignInit failed");
	}

	if (EVP_DigestSignUpdate(ctx, "test", 4) == -1) {
		fatal0("EVP_DigestSignUpdate failed");
	}

	blob_size = 0;
	if (EVP_DigestSignFinal(ctx, NULL, &blob_size) == -1) {
		fatal0("EVP_DigestSignFinal failed");
	}

	if ((blob = OPENSSL_malloc(blob_size)) == NULL) {
		fatal0("OPENSSL_malloc failed");
	}

	if (EVP_DigestSignFinal(ctx, blob, &blob_size) == -1) {
		fatal0("EVP_DigestSignFinal failed");
	}

	OPENSSL_free(blob);
	EVP_MD_CTX_destroy(ctx);
}

int main () {
	pkcs11h_certificate_id_list_t issuers, certs, temp;
	pkcs11h_certificate_t cert;
	pkcs11h_openssl_session_t session;
	CK_RV rv;

	printf ("Initializing pkcs11-helper\n");

	if ((rv = pkcs11h_initialize ()) != CKR_OK) {
		fatal ("pkcs11h_initialize failed", rv);
	}

	printf ("Registering pkcs11-helper hooks\n");

	if ((rv = pkcs11h_setLogHook (_pkcs11h_hooks_log, NULL)) != CKR_OK) {
		fatal ("pkcs11h_setLogHook failed", rv);
	}

	pkcs11h_setLogLevel (TEST_LOG_LEVEL);

	if ((rv = pkcs11h_setTokenPromptHook (_pkcs11h_hooks_token_prompt, NULL)) != CKR_OK) {
		fatal ("pkcs11h_setTokenPromptHook failed", rv);
	}

	if ((rv = pkcs11h_setPINPromptHook (_pkcs11h_hooks_pin_prompt, NULL)) != CKR_OK) {
		fatal ("pkcs11h_setPINPromptHook failed", rv);
	}

	printf ("Adding provider '%s'\n", TEST_PROVIDER);

	if (
		(rv = pkcs11h_addProvider (
			TEST_PROVIDER,
			TEST_PROVIDER,
			FALSE,
			PKCS11H_PRIVATEMODE_MASK_AUTO,
			PKCS11H_SLOTEVENT_METHOD_AUTO,
			0,
			FALSE
		)) != CKR_OK
	) {
		fatal ("pkcs11h_addProvider failed", rv);
	}

	mypause ("Please remove all tokens, press <Enter>: ");

	printf ("Enumerating token certificate (list should be empty, no prompt)\n");

	if (
		(rv = pkcs11h_certificate_enumCertificateIds (
			PKCS11H_ENUM_METHOD_CACHE,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			&issuers,
			&certs
		)) != CKR_OK
	) {
		fatal ("pkcs11h_certificate_enumCertificateIds failed", rv);
	}

	if (issuers != NULL || certs != NULL) {
		fatal ("No certificates should be found", rv);
	}

	mypause ("Please insert token, press <Enter>: ");

	printf ("Getting certificate cache, should be available certificates\n");

	if (
		(rv = pkcs11h_certificate_enumCertificateIds (
			PKCS11H_ENUM_METHOD_CACHE,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			&issuers,
			&certs
		)) != CKR_OK
	) {
		fatal ("pkcs11h_certificate_enumCertificateIds failed", rv);
	}

	for (temp = issuers;temp != NULL;temp = temp->next) {
		printf ("Issuer: %s\n", temp->certificate_id->displayName);
	}
	for (temp = certs;temp != NULL;temp = temp->next) {
		printf ("Certificate: %s\n", temp->certificate_id->displayName);
	}

	if (certs == NULL) {
		fatal ("No certificates found", rv);
	}

	pkcs11h_certificate_freeCertificateIdList (issuers);
	pkcs11h_certificate_freeCertificateIdList (certs);

	mypause ("Please remove token, press <Enter>: ");

	printf ("Getting certificate cache, should be similar to last\n");

	if (
		(rv = pkcs11h_certificate_enumCertificateIds (
			PKCS11H_ENUM_METHOD_CACHE,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			&issuers,
			&certs
		)) != CKR_OK
	) {
		fatal ("pkcs11h_certificate_enumCertificateIds failed", rv);
	}

	for (temp = issuers;temp != NULL;temp = temp->next) {
		printf ("Issuer: %s\n", temp->certificate_id->displayName);
	}
	for (temp = certs;temp != NULL;temp = temp->next) {
		printf ("Certificate: %s\n", temp->certificate_id->displayName);
	}

	if (certs == NULL) {
		fatal ("No certificates found", rv);
	}

	printf ("Creating certificate context\n");

	if (
		(rv = pkcs11h_certificate_create (
			certs->certificate_id,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			PKCS11H_PIN_CACHE_INFINITE,
			&cert
		)) != CKR_OK
	) {
		fatal ("pkcs11h_certificate_create failed", rv);
	}

	if ((session = pkcs11h_openssl_createSession(cert)) == NULL) {
		fatal0("pkcs11h_openssl_createSession failed");
	}

	printf ("Perforing signature #1 (you should be prompt for token and PIN)\n");

	sign_test (session);

	printf ("Perforing signature #2 (you should NOT be prompt for anything)\n");

	sign_test (session);

	mypause ("Please remove and insert token, press <Enter>: ");

	printf ("Perforing signature #3 (you should be prompt only for PIN)\n");

	sign_test (session);

	printf ("Perforing signature #4 (you should NOT be prompt for anything)\n");

	pkcs11h_openssl_freeSession(session);

	if (
		(rv = pkcs11h_certificate_create (
			certs->certificate_id,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			PKCS11H_PIN_CACHE_INFINITE,
			&cert
		)) != CKR_OK
	) {
		fatal ("pkcs11h_certificate_create failed", rv);
	}

	if ((session = pkcs11h_openssl_createSession(cert)) == NULL) {
		fatal0("pkcs11h_openssl_createSession failed");
	}

	sign_test (session);

	printf ("Terminating pkcs11-helper\n");

	pkcs11h_openssl_freeSession(session);

	pkcs11h_certificate_freeCertificateIdList (issuers);
	pkcs11h_certificate_freeCertificateIdList (certs);

	if ((rv = pkcs11h_terminate ()) != CKR_OK) {
		fatal ("pkcs11h_terminate failed", rv);
	}

	exit (0);
	return 0;
}

#endif
