#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../config.h"
#include <pkcs11-helper-1.0/pkcs11h-core.h>
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>

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

static
CK_RV
_deserialize (
	const char * const str,
	const PKCS11H_BOOL should_success
) {
	pkcs11h_certificate_id_t id = NULL;
	char *p = NULL;
	size_t max;
	CK_RV ret;
	CK_RV rv;

	ret = pkcs11h_certificate_deserializeCertificateId (
		&id,
		str
	);

	if (should_success && ret != CKR_OK) {
		fprintf(stderr, "String: %s\n", str);
		fatal("Should succeed", rv);
	}
	if (!should_success && ret == CKR_OK) {
		fprintf(stderr, "String: %s\n", str);
		fatal("Should fail", rv);
	}

	if (id != NULL) {
		if ((rv = pkcs11h_certificate_serializeCertificateId (
			NULL,
			&max,
			id
		)) != CKR_OK) {
			fatal("pkcs11h_certificate_serializeCertificateId", rv);
		}

		if ((p = malloc(max)) == NULL) {
			fatal("malloc", CKR_HOST_MEMORY);
		}

		if ((rv = pkcs11h_certificate_serializeCertificateId (
			p,
			&max,
			id
		)) != CKR_OK) {
			fatal("pkcs11h_certificate_serializeCertificateId(2)", rv);
		}

		if (strcmp(p, str)) {
			fprintf(stderr, "in: '%s' construct: '%s'\n", str, p);
			fatal("Fail serialize compare", CKR_FUNCTION_FAILED);
		}
	}

	if (p != NULL) {
		free(p);
	}

	if (id != NULL) {
		pkcs11h_certificate_freeCertificateId(id);
	}

	return ret;
}

int main () {
	CK_RV rv;
	int i;

	printf ("Initializing pkcs11-helper\n");

	if ((rv = pkcs11h_initialize ()) != CKR_OK) {
		fatal ("pkcs11h_initialize failed", rv);
	}

	printf ("Registering pkcs11-helper hooks\n");

	if ((rv = pkcs11h_setLogHook (_pkcs11h_hooks_log, NULL)) != CKR_OK) {
		fatal ("pkcs11h_setLogHook failed", rv);
	}

	pkcs11h_setLogLevel (TEST_LOG_LEVEL);

	printf ("Sanity\n");

	_deserialize("manufacturer/model/serial/label/02", TRUE);

	_deserialize("manufacturer/model/serial/label/0z", FALSE);

	_deserialize("manufa\\xggcturer/model/serial/label/02", FALSE);

	printf ("Components\n");

	const char *failure_string = "manu\\xff/model/serial/label\xee/0";
	char buffer[1024];

	for (i = 0; i < strlen(failure_string); i++) {
		strcpy(buffer, failure_string);
		buffer[i] = '\0';
		_deserialize(buffer, FALSE);
	}

	printf ("Terminating pkcs11-helper\n");

	if ((rv = pkcs11h_terminate ()) != CKR_OK) {
		fatal ("pkcs11h_terminate failed", rv);
	}

	exit (0);
	return 0;
}
