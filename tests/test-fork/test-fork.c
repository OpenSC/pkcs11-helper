#include <stdio.h>
#include <stdlib.h>
#include "../../config.h"
#include <pkcs11-helper-1.0/pkcs11h-core.h>

#if !defined(ENABLE_PKCS11H_CERTIFICATE) || defined(WIN32)
int main () {
	printf ("!win32, certificate, enum and crypto engine interfaces should be enabled for this test");
	exit (77);
	return 0;
}
#else

#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#include <sys/wait.h>
#include <unistd.h>

static
void
fatal (const char * const m, CK_RV rv) {
	fprintf (stderr, "%s - %08lu - %s\n", m, rv, pkcs11h_getMessage (rv));
	exit (1);
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

int main () {
	pkcs11h_certificate_id_list_t issuers, certs;
	pid_t pid;
	CK_RV rv;

	printf ("Version: %08x\n", pkcs11h_getVersion ());
	printf ("Features: %08x\n", pkcs11h_getFeatures ());

	printf ("Initializing pkcs11-helper\n");

	if ((rv = pkcs11h_initialize ()) != CKR_OK) {
		fatal ("pkcs11h_initialize failed", rv);
	}

	pkcs11h_setForkMode(TRUE);

	printf ("Registering pkcs11-helper hooks\n");

	if ((rv = pkcs11h_setLogHook (_pkcs11h_hooks_log, NULL)) != CKR_OK) {
		fatal ("pkcs11h_setLogHook failed", rv);
	}

	pkcs11h_setLogLevel (TEST_LOG_LEVEL);

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

	printf ("Forking pkcs11-helper\n");
	fflush(stdout);

	if ((pid = fork()) == -1) {
		fatal ("fork failed", CKR_GENERAL_ERROR);
	}
	else if (pid == 0) {
		printf ("Child fork fixup\n");
		pkcs11h_forkFixup();
		printf ("Child Enum certs\n");
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
		printf ("Child termination\n");
		if ((rv = pkcs11h_terminate ()) != CKR_OK) {
			fatal ("pkcs11h_terminate failed", rv);
		}
		exit (0);
	}
	else {
		printf ("Parent Enum certs\n");
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
		waitpid(pid, NULL, 0);
	}

	printf ("Terminating pkcs11-helper\n");

	if ((rv = pkcs11h_terminate ()) != CKR_OK) {
		fatal ("pkcs11h_terminate failed", rv);
	}

	exit (0);
	return 0;
}

#endif
