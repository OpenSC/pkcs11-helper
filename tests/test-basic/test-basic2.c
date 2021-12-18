#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../config.h"
#include <pkcs11-helper-1.0/pkcs11h-core.h>

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
void
_pkcs11h_hooks_provider_destroy (
	IN void * const * global_data,
	IN const char * const reference
) {
	fprintf (stdout, "Provider '%s' destroyed\n", reference);
	fflush (stdout);
}

int main () {
	struct {
		char *p;
		char *v;
	} props[] = {
		{"location", TEST_PROVIDER},
		{"allow_protected_auth", "1"},
		{"mask_private_mode", "2"},
		{"slot_event_method", "3"},
		{"slot_poll_interval", "0x55"},
		{"cert_is_private", "1"},
		{NULL, NULL}
	}, *p;

	const char * reference = "reference1";
	CK_C_INITIALIZE_ARGS init_args;
	CK_C_INITIALIZE_ARGS_PTR init_args_ptr = &init_args;
	CK_RV rv;

	printf ("Version: %08x\n", pkcs11h_getVersion ());
	printf ("Features: %08x\n", pkcs11h_getFeatures ());

	printf ("Initializing pkcs11-helper\n");

	if ((rv = pkcs11h_initialize ()) != CKR_OK) {
		fatal ("pkcs11h_initialize failed", rv);
	}

	printf ("Registering pkcs11-helper hooks\n");

	if ((rv = pkcs11h_setLogHook (_pkcs11h_hooks_log, NULL)) != CKR_OK) {
		fatal ("pkcs11h_setLogHook failed", rv);
	}

	pkcs11h_setLogLevel (TEST_LOG_LEVEL);

	printf ("Registering provider '%s'\n", TEST_PROVIDER);
	if ((rv = pkcs11h_registerProvider (reference)) != CKR_OK) {
		fatal ("pkcs11h_registerProvider failed", rv);
	}

	for (p = props; p->p != NULL; p++) {
		printf("Setting property '%s'='%s'\n", p->p, p->v);
		if (
			(rv = pkcs11h_setProviderPropertyByName (
				reference,
				p->p,
				p->v
			)) != CKR_OK
		) {
			fatal ("pkcs11h_setProviderPropertyByName failed", rv);
		}
	}

	{
		void *p;
		p = &_pkcs11h_hooks_provider_destroy;
		pkcs11h_setProviderProperty(reference, PKCS11H_PROVIDER_PROPERTY_PROVIDER_DESTRUCT_HOOK, &p, sizeof(p));
	}

	memset(&init_args, 0, sizeof(init_args));
	init_args.flags = CKF_OS_LOCKING_OK;
	if (
		(rv = pkcs11h_setProviderProperty (
			reference,
			PKCS11H_PROVIDER_PROPERTY_INIT_ARGS,
			&init_args_ptr,
			sizeof(init_args_ptr)
		)) != CKR_OK
	) {
		fatal ("pkcs11h_setProviderProperty failed for PKCS11H_PROVIDER_PROPERTY_INIT_ARGS", rv);
	}

	if ((rv = pkcs11h_initializeProvider (reference)) != CKR_OK) {
		fatal ("pkcs11h_initializeProvider failed", rv);
	}

	if ((rv = pkcs11h_removeProvider (reference)) != CKR_OK) {
		fatal ("pkcs11h_initializeProvider failed", rv);
	}

	printf ("Terminating pkcs11-helper\n");

	if ((rv = pkcs11h_terminate ()) != CKR_OK) {
		fatal ("pkcs11h_terminate failed", rv);
	}

	exit (0);
	return 0;
}
