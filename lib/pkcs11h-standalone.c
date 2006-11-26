/*
 * Copyright (c) 2005-2006 Alon Bar-Lev <alon.barlev@gmail.com>
 * All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, or the OpenIB.org BSD license.
 *
 * GNU General Public License (GPL) Version 2
 * ===========================================
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING.GPL included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * OpenIB.org BSD license
 * =======================
 * Redistribution and use in source and binary forms, with or without modifi-
 * cation, are permitted provided that the following conditions are met:
 *
 *   o  Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   o  Redistributions in binary form must reproduce the above copyright no-
 *      tice, this list of conditions and the following disclaimer in the do-
 *      cumentation and/or other materials provided with the distribution.
 *
 *   o  The names of the contributors may not be used to endorse or promote
 *      products derived from this software without specific prior written
 *      permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LI-
 * ABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUEN-
 * TIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEV-
 * ER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABI-
 * LITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "common.h"

#if defined(ENABLE_PKCS11H_STANDALONE)

#include "_pkcs11h-mem.h"
#include "_pkcs11h-core.h"
#include "_pkcs11h-util.h"
#include "_pkcs11h-crypto.h"
#include "_pkcs11h-session.h"
#include "_pkcs11h-token.h"
#include <pkcs11-helper-1.0/pkcs11h-standalone.h>

void
pkcs11h_standalone_dump_slots (
	IN const pkcs11h_output_print_t my_output,
	IN void * const global_data,
	IN const char * const provider,
	IN const char * const prms[]
) {
	CK_RV rv = CKR_OK;

	pkcs11h_provider_t pkcs11h_provider;

	PKCS11H_ASSERT (my_output!=NULL);
	/*PKCS11H_ASSERT (global_data) NOT NEEDED */
	PKCS11H_ASSERT (provider!=NULL);

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_initialize ()) != CKR_OK
	) {
		my_output (global_data, "PKCS#11: Cannot initialize interface %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_addProvider (
			provider,
			provider,
			FALSE,
			PKCS11H_PRIVATEMODE_MASK_AUTO,
			PKCS11H_SLOTEVENT_METHOD_AUTO,
			0,
			FALSE
		)) != CKR_OK
	) {
		my_output (global_data, "PKCS#11: Cannot initialize provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	/*
	 * our provider is head
	 */
	if (rv == CKR_OK) {
		pkcs11h_provider = g_pkcs11h_data->providers;
		if (pkcs11h_provider == NULL || !pkcs11h_provider->enabled) {
			my_output (global_data, "PKCS#11: Cannot get provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
			rv = CKR_GENERAL_ERROR;
		}
	}

	if (rv == CKR_OK) {
		CK_INFO info;
		
		if ((rv = pkcs11h_provider->f->C_GetInfo (&info)) != CKR_OK) {
			my_output (global_data, "PKCS#11: Cannot get PKCS#11 provider information %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
			rv = CKR_OK;
		}
		else {
			char manufacturerID[sizeof (info.manufacturerID)+1];
	
			_pkcs11h_util_fixupFixedString (
				manufacturerID,
				(char *)info.manufacturerID,
				sizeof (info.manufacturerID)
			);
	
			my_output (
				global_data,
				(
					"Provider Information:\n"
					"\tcryptokiVersion:\t%u.%u\n"
					"\tmanufacturerID:\t\t%s\n"
					"\tflags:\t\t\t%08x\n"
					"\n"
				),
				info.cryptokiVersion.major,
				info.cryptokiVersion.minor,
				manufacturerID,
				(unsigned)info.flags
			);
		}
	}
	
	if (rv == CKR_OK) {
		CK_SLOT_ID_PTR slots = NULL;
		CK_ULONG slotnum;
		CK_SLOT_ID slot_index;
		
		if (
			 _pkcs11h_session_getSlotList (
				pkcs11h_provider,
				CK_FALSE,
				&slots,
				&slotnum
			) != CKR_OK
		) {
			my_output (global_data, "PKCS#11: Cannot get slot list %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
		}
		else {
			my_output (
				global_data,
				"The following slots are available for use with this provider.\n"
			);

			if (prms != NULL) {
				my_output (
					global_data,
					(
						"Each slot shown below may be used as a parameter to a\n"
						"%s and %s options.\n"
					),
					prms[0],
					prms[1]
				);
			}

			my_output (
				global_data,
				(
					"\n"
					"Slots: (id - name)\n"
				)
			);

			for (slot_index=0;slot_index < slotnum;slot_index++) {
				CK_SLOT_INFO info;
	
				if (
					(rv = pkcs11h_provider->f->C_GetSlotInfo (
						slots[slot_index],
						&info
					)) == CKR_OK
				) {
					char current_name[sizeof (info.slotDescription)+1];
				
					_pkcs11h_util_fixupFixedString (
						current_name,
						(char *)info.slotDescription,
						sizeof (info.slotDescription)
					);
	
					my_output (global_data, "\t%lu - %s\n", slots[slot_index], current_name);
				}
			}
		}

		if (slots != NULL) {
			_pkcs11h_mem_free ((void *)&slots);
		}
	}
	
	pkcs11h_terminate ();
}

static
PKCS11H_BOOL
_pkcs11h_standalone_dump_objects_pin_prompt (
	IN void * const global_data,
	IN void * const user_data,
	IN const pkcs11h_token_id_t token,
	IN const unsigned retry,
	OUT char * const pin,
	IN const size_t pin_max
) {
	(void)user_data;
	(void)token;

	/*
	 * Don't lock card
	 */
	if (retry == 0) {
		strncpy (pin, (char *)global_data, pin_max);
		return TRUE;
	}
	else {
		return FALSE;
	}
}

static
void
_pkcs11h_standalone_dump_objects_hex (
	IN const unsigned char * const p,
	IN const size_t p_size,
	OUT char * const sz,
	IN const size_t max,
	IN const char * const prefix
) {
	size_t j;

	sz[0] = '\0';

	for (j=0;j<p_size;j+=16) {
		char line[3*16+1];
		size_t k;

		line[0] = '\0';
		for (k=0;k<16 && j+k<p_size;k++) {
			sprintf (line+strlen (line), "%02x ", p[j+k]);
		}

		strncat (
			sz,
			prefix,
			max-1-strlen (sz)
		);
		strncat (
			sz,
			line,
			max-1-strlen (sz)
		);
		strncat (
			sz,
			"\n",
			max-1-strlen (sz)
		);
	}

	sz[max-1] = '\0';
}
	
void
pkcs11h_standalone_dump_objects (
	IN const pkcs11h_output_print_t my_output,
	IN void * const global_data,
	IN const char * const provider,
	IN const char * const slot,
	IN const char * const pin,
	IN const char * const prms[]
) {
	CK_SLOT_ID s;
	CK_RV rv = CKR_OK;

	pkcs11h_provider_t pkcs11h_provider = NULL;
	pkcs11h_token_id_t token_id = NULL;
	pkcs11h_session_t session = NULL;

	PKCS11H_ASSERT (my_output!=NULL);
	/*PKCS11H_ASSERT (global_data) NOT NEEDED */
	PKCS11H_ASSERT (provider!=NULL);
	PKCS11H_ASSERT (slot!=NULL);
	PKCS11H_ASSERT (pin!=NULL);

	s = atoi (slot);

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_initialize ()) != CKR_OK
	) {
		my_output (global_data, "PKCS#11: Cannot initialize interface %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_setPINPromptHook (_pkcs11h_standalone_dump_objects_pin_prompt, (void *)pin)) != CKR_OK
	) {
		my_output (global_data, "PKCS#11: Cannot set hooks %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	if (
		rv == CKR_OK &&
		(rv = pkcs11h_addProvider (
			provider,
			provider,
			FALSE,
			PKCS11H_PRIVATEMODE_MASK_AUTO,
			PKCS11H_SLOTEVENT_METHOD_AUTO,
			0,
			FALSE
		)) != CKR_OK
	) {
		my_output (global_data, "PKCS#11: Cannot initialize provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
	}

	/*
	 * our provider is head
	 */
	if (rv == CKR_OK) {
		pkcs11h_provider = g_pkcs11h_data->providers;
		if (pkcs11h_provider == NULL || !pkcs11h_provider->enabled) {
			my_output (global_data, "PKCS#11: Cannot get provider %ld-'%s'\n", rv, pkcs11h_getMessage (rv));
			rv = CKR_GENERAL_ERROR;
		}
	}

	if (rv == CKR_OK) {
		CK_TOKEN_INFO info;
		
		if (
			(rv = pkcs11h_provider->f->C_GetTokenInfo (
				s,
				&info
			)) != CKR_OK
		) {
			my_output (global_data, "PKCS#11: Cannot get token information for slot %ld %ld-'%s'\n", s, rv, pkcs11h_getMessage (rv));
			/* Ignore this error */
			rv = CKR_OK;
		}
		else {
			char label[sizeof (info.label)+1];
			char manufacturerID[sizeof (info.manufacturerID)+1];
			char model[sizeof (info.model)+1];
			char serialNumberNumber[sizeof (info.serialNumber)+1];
			
			_pkcs11h_util_fixupFixedString (
				label,
				(char *)info.label,
				sizeof (info.label)
			);
			_pkcs11h_util_fixupFixedString (
				manufacturerID,
				(char *)info.manufacturerID,
				sizeof (info.manufacturerID)
			);
			_pkcs11h_util_fixupFixedString (
				model,
				(char *)info.model,
				sizeof (info.model)
			);
			_pkcs11h_util_fixupFixedString (
				serialNumberNumber,
				(char *)info.serialNumber,
				sizeof (info.serialNumber)
			);
	
			my_output (
				global_data,
				(
					"Token Information:\n"
					"\tlabel:\t\t%s\n"
					"\tmanufacturerID:\t%s\n"
					"\tmodel:\t\t%s\n"
					"\tserialNumber:\t%s\n"
					"\tflags:\t\t%08x\n"
					"\n"
				),
				label,
				manufacturerID,
				model,
				serialNumberNumber,
				(unsigned)info.flags
			);

			if (prms!=NULL) {
				my_output (
					global_data,
					(
						"You can access this token using\n"
						"%s \"label\" %s \"%s\" options.\n"
						"\n"
					),
					prms[0],
					prms[1],
					label
				);
			}

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_token_getTokenId (
					&info,
					&token_id
				)) != CKR_OK
			) {
				my_output (global_data, "PKCS#11: Cannot get token id for slot %ld %ld-'%s'\n", s, rv, pkcs11h_getMessage (rv));		
				rv = CKR_OK;
			}
		}
	}

	if (token_id != NULL) {
		if (
			(rv = _pkcs11h_session_getSessionByTokenId (
				token_id,
				&session
			)) != CKR_OK
		) {
			my_output (global_data, "PKCS#11: Cannot session for token '%s' %ld-'%s'\n", token_id->display, rv, pkcs11h_getMessage (rv));		
			rv = CKR_OK;
		}
	}

	if (session != NULL) {
		CK_OBJECT_HANDLE *objects = NULL;
		CK_ULONG objects_found = 0;
		CK_ULONG i;

		if (
			(rv = _pkcs11h_session_login (
				session,
				FALSE,
				TRUE,
				NULL,
				PKCS11H_PROMPT_MASK_ALLOW_PIN_PROMPT
			)) != CKR_OK
		) {
			my_output (global_data, "PKCS#11: Cannot open session to token '%s' %ld-'%s'\n", session->token_id->display, rv, pkcs11h_getMessage (rv));
		}
	
		my_output (
			global_data,
			"The following objects are available for use with this token.\n"
		);

		if (prms != NULL) {
			my_output (
				global_data,
				(
					"Each object shown below may be used as a parameter to\n"
					"%s and %s options.\n"
				),
				prms[2],
				prms[3]
			);
		}

		my_output (
			global_data,
			"\n"
		);

		if (
			rv == CKR_OK &&
			(rv = _pkcs11h_session_findObjects (
				session,
				NULL,
				0,
				&objects,
				&objects_found
			)) != CKR_OK
		) {
			my_output (global_data, "PKCS#11: Cannot query objects for token '%s' %ld-'%s'\n", session->token_id->display, rv, pkcs11h_getMessage (rv));
		}
	
		for (i=0;rv == CKR_OK && i < objects_found;i++) {
			CK_OBJECT_CLASS attrs_class = 0;
			CK_ATTRIBUTE attrs[] = {
				{CKA_CLASS, &attrs_class, sizeof (attrs_class)}
			};

			if (
				_pkcs11h_session_getObjectAttributes (
					session,
					objects[i],
					attrs,
					sizeof (attrs) / sizeof (CK_ATTRIBUTE)
				) == CKR_OK
			) {
				if (attrs_class == CKO_CERTIFICATE) {
					CK_ATTRIBUTE attrs_cert[] = {
						{CKA_ID, NULL, 0},
						{CKA_LABEL, NULL, 0},
						{CKA_VALUE, NULL, 0}
					};
					unsigned char *attrs_id = NULL;
					int attrs_id_size = 0;
					unsigned char *attrs_value = NULL;
					int attrs_value_size = 0;
					char *attrs_label = NULL;
					char hex_id[1024];
					char subject[1024];
					char serialNumber[1024];
					time_t notAfter = 0;

					subject[0] = '\0';
					serialNumber[0] = '\0';


					if (
						_pkcs11h_session_getObjectAttributes (
							session,
							objects[i],
							attrs_cert,
							sizeof (attrs_cert) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_mem_malloc (
							(void *)&attrs_label,
							attrs_cert[1].ulValueLen+1
						) == CKR_OK
					) {
						attrs_id = (unsigned char *)attrs_cert[0].pValue;
						attrs_id_size = attrs_cert[0].ulValueLen;
						attrs_value = (unsigned char *)attrs_cert[2].pValue;
						attrs_value_size = attrs_cert[2].ulValueLen;

						memset (attrs_label, 0, attrs_cert[1].ulValueLen+1);
						memmove (attrs_label, attrs_cert[1].pValue, attrs_cert[1].ulValueLen);
						_pkcs11h_standalone_dump_objects_hex (
							attrs_id,
							attrs_id_size,
							hex_id,
							sizeof (hex_id),
							"\t\t"
						);
					}

					if (attrs_value != NULL) {
						if (
							!g_pkcs11h_crypto_engine.certificate_get_dn (
								g_pkcs11h_crypto_engine.global_data,
								attrs_value,
								attrs_value_size,
								subject,
								sizeof (subject)
							)
						) {
							subject[0] = '\x0';
						}

						if (
							!g_pkcs11h_crypto_engine.certificate_get_expiration (
								g_pkcs11h_crypto_engine.global_data,
								attrs_value,
								attrs_value_size,
								&notAfter
							)
						) {
							notAfter = (time_t)0;
						}

						if (
							!g_pkcs11h_crypto_engine.certificate_get_serial (
								g_pkcs11h_crypto_engine.global_data,
								attrs_value,
								attrs_value_size,
								serialNumber,
								sizeof (serialNumber)
							)
						) {
							serialNumber[0] = '\x0';
						}
					}

					my_output (
						global_data,
						(
							"Object\n"
							"\tType:\t\t\tCertificate\n"
							"\tCKA_ID:\n"
							"%s"
							"\tCKA_LABEL:\t\t%s\n"
							"\tsubject:\t\t%s\n"
							"\tserialNumber:\t\t%s\n"
							"\tnotAfter:\t\t%s\n"
						),
						hex_id,
						attrs_label,
						subject,
						serialNumber,
						asctime (localtime (&notAfter))
					);

					if (attrs_label != NULL) {
						_pkcs11h_mem_free ((void *)&attrs_label);
						attrs_label = NULL;
					}

					_pkcs11h_session_freeObjectAttributes (
						attrs_cert,
						sizeof (attrs_cert) / sizeof (CK_ATTRIBUTE)
					);
				}
				else if (attrs_class == CKO_PRIVATE_KEY) {
					CK_BBOOL sign_recover = CK_FALSE;
					CK_BBOOL sign = CK_FALSE;
					CK_ATTRIBUTE attrs_key[] = {
						{CKA_SIGN, &sign, sizeof (sign)},
						{CKA_SIGN_RECOVER, &sign_recover, sizeof (sign_recover)}
					};
					CK_ATTRIBUTE attrs_key_common[] = {
						{CKA_ID, NULL, 0},
						{CKA_LABEL, NULL, 0}
					};
					unsigned char *attrs_id = NULL;
					int attrs_id_size = 0;
					char *attrs_label = NULL;
					char hex_id[1024];

					pkcs11h_provider->f->C_GetAttributeValue (
						session->session_handle,
						objects[i],
						attrs_key,
						sizeof (attrs_key) / sizeof (CK_ATTRIBUTE)
					);

					if (
						_pkcs11h_session_getObjectAttributes (
							session,
							objects[i],
							attrs_key_common,
							sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_mem_malloc (
							(void *)&attrs_label,
							attrs_key_common[1].ulValueLen+1
						) == CKR_OK
					) {
						attrs_id = (unsigned char *)attrs_key_common[0].pValue;
						attrs_id_size = attrs_key_common[0].ulValueLen;

						memset (attrs_label, 0, attrs_key_common[1].ulValueLen+1);
						memmove (attrs_label, attrs_key_common[1].pValue, attrs_key_common[1].ulValueLen);

						_pkcs11h_standalone_dump_objects_hex (
							attrs_id,
							attrs_id_size,
							hex_id,
							sizeof (hex_id),
							"\t\t"
						);
							
					}

					my_output (
						global_data,
						(
							"Object\n"
							"\tType:\t\t\tPrivate Key\n"
							"\tCKA_ID:\n"
							"%s"
							"\tCKA_LABEL:\t\t%s\n"
							"\tCKA_SIGN:\t\t%s\n"
							"\tCKA_SIGN_RECOVER:\t%s\n"
						),
						hex_id,
						attrs_label,
						sign ? "TRUE" : "FALSE",
						sign_recover ? "TRUE" : "FALSE"
					);

					if (attrs_label != NULL) {
						_pkcs11h_mem_free ((void *)&attrs_label);
						attrs_label = NULL;
					}

					_pkcs11h_session_freeObjectAttributes (
						attrs_key_common,
						sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
					);
				}
				else if (attrs_class == CKO_PUBLIC_KEY) {
					CK_ATTRIBUTE attrs_key_common[] = {
						{CKA_ID, NULL, 0},
						{CKA_LABEL, NULL, 0}
					};
					unsigned char *attrs_id = NULL;
					int attrs_id_size = 0;
					char *attrs_label = NULL;
					char hex_id[1024];

					if (
						_pkcs11h_session_getObjectAttributes (
							session,
							objects[i],
							attrs_key_common,
							sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_mem_malloc (
							(void *)&attrs_label,
							attrs_key_common[1].ulValueLen+1
						) == CKR_OK
					) {
						attrs_id = (unsigned char *)attrs_key_common[0].pValue;
						attrs_id_size = attrs_key_common[0].ulValueLen;

						memset (attrs_label, 0, attrs_key_common[1].ulValueLen+1);
						memmove (attrs_label, attrs_key_common[1].pValue, attrs_key_common[1].ulValueLen);

						_pkcs11h_standalone_dump_objects_hex (
							attrs_id,
							attrs_id_size,
							hex_id,
							sizeof (hex_id),
							"\t\t"
						);
							
					}

					my_output (
						global_data,
						(
							"Object\n"
							"\tType:\t\t\tPublic Key\n"
							"\tCKA_ID:\n"
							"%s"
							"\tCKA_LABEL:\t\t%s\n"
						),
						hex_id,
						attrs_label
					);

					_pkcs11h_mem_free ((void *)&attrs_label);

					_pkcs11h_session_freeObjectAttributes (
						attrs_key_common,
						sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
					);
				}
				else if (attrs_class == CKO_DATA) {
					CK_ATTRIBUTE attrs_key_common[] = {
						{CKA_APPLICATION, NULL, 0},
						{CKA_LABEL, NULL, 0}
					};
					char *attrs_application = NULL;
					char *attrs_label = NULL;

					if (
						_pkcs11h_session_getObjectAttributes (
							session,
							objects[i],
							attrs_key_common,
							sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
						) == CKR_OK &&
						_pkcs11h_mem_malloc (
							(void *)&attrs_application,
							attrs_key_common[0].ulValueLen+1
						) == CKR_OK &&
						_pkcs11h_mem_malloc (
							(void *)&attrs_label,
							attrs_key_common[1].ulValueLen+1
						) == CKR_OK
					) {
						memset (attrs_application, 0, attrs_key_common[0].ulValueLen+1);
						memmove (attrs_application, attrs_key_common[0].pValue, attrs_key_common[0].ulValueLen);
						memset (attrs_label, 0, attrs_key_common[1].ulValueLen+1);
						memmove (attrs_label, attrs_key_common[1].pValue, attrs_key_common[1].ulValueLen);
					}

					my_output (
						global_data,
						(
							"Object\n"
							"\tType:\t\t\tData\n"
							"\tCKA_APPLICATION\t\t%s\n"
							"\tCKA_LABEL:\t\t%s\n"
						),
						attrs_application,
						attrs_label
					);

					_pkcs11h_mem_free ((void *)&attrs_application);
					_pkcs11h_mem_free ((void *)&attrs_label);

					_pkcs11h_session_freeObjectAttributes (
						attrs_key_common,
						sizeof (attrs_key_common) / sizeof (CK_ATTRIBUTE)
					);
				}
				else {
					my_output (
						global_data,
						(
							"Object\n"
							"\tType:\t\t\tUnsupported\n"
						)
					);
				}
			}

			_pkcs11h_session_freeObjectAttributes (
				attrs,
				sizeof (attrs) / sizeof (CK_ATTRIBUTE)
			);

			/*
			 * Ignore any error and
			 * perform next iteration
			 */
			rv = CKR_OK;
		}
	
		if (objects != NULL) {
			_pkcs11h_mem_free ((void *)&objects);
		}

		/*
		 * Ignore this error
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
	
	pkcs11h_terminate ();
}

#endif				/* ENABLE_PKCS11H_STANDALONE */
