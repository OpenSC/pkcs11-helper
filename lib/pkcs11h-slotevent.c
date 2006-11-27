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

#if defined(ENABLE_PKCS11H_SLOTEVENT)

#include "_pkcs11h-mem.h"
#include "_pkcs11h-session.h"
#include "_pkcs11h-slotevent.h"

static
unsigned long
__pkcs11h_slotevent_checksum (
	IN const unsigned char * const p,
	IN const size_t s
);

static
void *
__pkcs11h_slotevent_provider (
	IN void *p
);

static
void *
__pkcs11h_slotevent_manager (
	IN void *p
);

static
unsigned long
__pkcs11h_slotevent_checksum (
	IN const unsigned char * const p,
	IN const size_t s
) {
	unsigned long r = 0;
	size_t i;
	for (i=0;i<s;i++) {
		r += p[i];
	}
	return r;
}

static
void *
__pkcs11h_slotevent_provider (
	IN void *p
) {
	pkcs11h_provider_t provider = (pkcs11h_provider_t)p;
	CK_SLOT_ID slot;
	CK_RV rv = CKR_OK;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_slotevent_provider provider='%s' entry",
		provider->manufacturerID
	);

	if (rv == CKR_OK && !provider->enabled) {
		rv = CKR_OPERATION_NOT_INITIALIZED;
	}

	if (rv == CKR_OK) {

		if (provider->slot_poll_interval == 0) {
			provider->slot_poll_interval = PKCS11H_DEFAULT_SLOTEVENT_POLL;
		}

		/*
		 * If we cannot finalize, we cannot cause
		 * WaitForSlotEvent to terminate
		 */
		if (!provider->should_finalize) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Setup slotevent provider='%s' mode hardset to poll",
				provider->manufacturerID
			);
			provider->slot_event_method = PKCS11H_SLOTEVENT_METHOD_POLL;
		}

		if (
			provider->slot_event_method == PKCS11H_SLOTEVENT_METHOD_AUTO ||
			provider->slot_event_method == PKCS11H_SLOTEVENT_METHOD_TRIGGER
		) { 
			if (
				provider->f->C_WaitForSlotEvent (
					CKF_DONT_BLOCK,
					&slot,
					NULL_PTR
				) == CKR_FUNCTION_NOT_SUPPORTED
			) {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Setup slotevent provider='%s' mode is poll",
					provider->manufacturerID
				);

				provider->slot_event_method = PKCS11H_SLOTEVENT_METHOD_POLL;
			}
			else {
				PKCS11H_DEBUG (
					PKCS11H_LOG_DEBUG1,
					"PKCS#11: Setup slotevent provider='%s' mode is trigger",
					provider->manufacturerID
				);

				provider->slot_event_method = PKCS11H_SLOTEVENT_METHOD_TRIGGER;
			}
		}
	}

	if (provider->slot_event_method == PKCS11H_SLOTEVENT_METHOD_TRIGGER) {
		while (
			!g_pkcs11h_data->slotevent.should_terminate &&
			provider->enabled &&
			rv == CKR_OK &&
			(rv = provider->f->C_WaitForSlotEvent (
				0,
				&slot,
				NULL_PTR
			)) == CKR_OK
		) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Slotevent provider='%s' event",
				provider->manufacturerID
			);

			_pkcs11h_threading_condSignal (&g_pkcs11h_data->slotevent.cond_event);
		}
	}
	else {
		unsigned long ulLastChecksum = 0;
		PKCS11H_BOOL is_first_time = TRUE;

		while (
			!g_pkcs11h_data->slotevent.should_terminate &&
			provider->enabled &&
			rv == CKR_OK
		) {
			unsigned long ulCurrentChecksum = 0;

			CK_SLOT_ID_PTR slots = NULL;
			CK_ULONG slotnum;

			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Slotevent provider='%s' poll",
				provider->manufacturerID
			);

			if (
				rv == CKR_OK &&
				(rv = _pkcs11h_session_getSlotList (
					provider,
					TRUE,
					&slots,
					&slotnum
				)) == CKR_OK
			) {
				CK_ULONG i;
				
				for (i=0;i<slotnum;i++) {
					CK_TOKEN_INFO info;

					if (provider->f->C_GetTokenInfo (slots[i], &info) == CKR_OK) {
						ulCurrentChecksum += (
							__pkcs11h_slotevent_checksum (
								info.label,
								sizeof (info.label)
							) +
							__pkcs11h_slotevent_checksum (
								info.manufacturerID,
								sizeof (info.manufacturerID)
							) +
							__pkcs11h_slotevent_checksum (
								info.model,
								sizeof (info.model)
							) +
							__pkcs11h_slotevent_checksum (
								info.serialNumber,
								sizeof (info.serialNumber)
							)
						);
					}
				}
			}
			
			if (rv == CKR_OK) {
				if (is_first_time) {
					is_first_time = FALSE;
				}
				else {
					if (ulLastChecksum != ulCurrentChecksum) {
						PKCS11H_DEBUG (
							PKCS11H_LOG_DEBUG1,
							"PKCS#11: Slotevent provider='%s' event",
							provider->manufacturerID
						);

						_pkcs11h_threading_condSignal (&g_pkcs11h_data->slotevent.cond_event);
					}
				}
				ulLastChecksum = ulCurrentChecksum;
			}

			if (slots != NULL) {
				_pkcs11h_mem_free ((void *)&slots);
			}
			
			if (!g_pkcs11h_data->slotevent.should_terminate) {
				_pkcs11h_threading_sleep (provider->slot_poll_interval);
			}
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_slotevent_provider provider='%s' return",
		provider->manufacturerID
	);

	return NULL;
}

static
void *
__pkcs11h_slotevent_manager (
	IN void *p
) {
	PKCS11H_BOOL first_time = TRUE;

	(void)p;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_slotevent_manager entry"
	);

	/*
	 * Trigger hook, so application may
	 * depend on initial slot change
	 */
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG1,
		"PKCS#11: Calling slotevent hook"
	);
	g_pkcs11h_data->hooks.slotevent (g_pkcs11h_data->hooks.slotevent_data);

	while (
		first_time ||	/* Must enter wait or mutex will never be free */
		!g_pkcs11h_data->slotevent.should_terminate
	) {
		pkcs11h_provider_t current_provider;

		first_time = FALSE;

		/*
		 * Start each provider thread
		 * if not already started.
		 * This is required in order to allow
		 * adding new providers.
		 */
		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: __pkcs11h_slotevent_manager examine provider list"
		);
		for (
			current_provider = g_pkcs11h_data->providers;
			current_provider != NULL;
			current_provider = current_provider->next
		) {
			if (current_provider->enabled) {
				if (current_provider->slotevent_thread == PKCS11H_THREAD_NULL) {
					PKCS11H_DEBUG (
						PKCS11H_LOG_DEBUG2,
						"PKCS#11: __pkcs11h_slotevent_manager found enabled provider without thread"
					);
					_pkcs11h_threading_threadStart (
						&current_provider->slotevent_thread,
						__pkcs11h_slotevent_provider,
						current_provider
					);
				}
			}
			else {
				if (current_provider->slotevent_thread != PKCS11H_THREAD_NULL) {
					PKCS11H_DEBUG (
						PKCS11H_LOG_DEBUG2,
						"PKCS#11: __pkcs11h_slotevent_manager found disabled provider with thread"
					);
					_pkcs11h_threading_threadJoin (&current_provider->slotevent_thread);
				}
			}
		}

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: __pkcs11h_slotevent_manager waiting for slotevent"
		);
		_pkcs11h_threading_condWait (&g_pkcs11h_data->slotevent.cond_event, PKCS11H_COND_INFINITE);

		if (g_pkcs11h_data->slotevent.skip_event) {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Slotevent skipping event"
			);
			g_pkcs11h_data->slotevent.skip_event = FALSE;
		}
		else {
			PKCS11H_DEBUG (
				PKCS11H_LOG_DEBUG1,
				"PKCS#11: Calling slotevent hook"
			);
			g_pkcs11h_data->hooks.slotevent (g_pkcs11h_data->hooks.slotevent_data);
		}
	}

	{
		pkcs11h_provider_t current_provider;

		PKCS11H_DEBUG (
			PKCS11H_LOG_DEBUG2,
			"PKCS#11: __pkcs11h_slotevent_manager joining threads"
		);


		for (
			current_provider = g_pkcs11h_data->providers;
			current_provider != NULL;
			current_provider = current_provider->next
		) {
			if (current_provider->slotevent_thread != PKCS11H_THREAD_NULL) {
				_pkcs11h_threading_threadJoin (&current_provider->slotevent_thread);
			}
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: __pkcs11h_slotevent_manager return"
	);

	return NULL;
}

CK_RV
_pkcs11h_slotevent_init (void) {
	CK_RV rv = CKR_OK;

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_init entry"
	);

	if (!g_pkcs11h_data->slotevent.initialized) {
		if (rv == CKR_OK) {
			rv = _pkcs11h_threading_condInit (&g_pkcs11h_data->slotevent.cond_event);
		}
		
		if (rv == CKR_OK) {
			rv = _pkcs11h_threading_threadStart (
				&g_pkcs11h_data->slotevent.thread,
				__pkcs11h_slotevent_manager,
				NULL
			);
		}
		
		if (rv == CKR_OK) {
			g_pkcs11h_data->slotevent.initialized = TRUE;
		}
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_init return rv=%ld-'%s'",
		rv,
		pkcs11h_getMessage (rv)
	);

	return rv;
}

CK_RV
_pkcs11h_slotevent_notify (void) {
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_notify entry"
	);

	if (g_pkcs11h_data->slotevent.initialized) {
		g_pkcs11h_data->slotevent.skip_event = TRUE;
		_pkcs11h_threading_condSignal (&g_pkcs11h_data->slotevent.cond_event);
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_notify return"
	);

	return CKR_OK;
}

CK_RV
_pkcs11h_slotevent_terminate_force (void) {
	if (g_pkcs11h_data->slotevent.initialized) {
		_pkcs11h_threading_condFree (&g_pkcs11h_data->slotevent.cond_event);
		g_pkcs11h_data->slotevent.initialized = FALSE;
	}

	return CKR_OK;
}

CK_RV
_pkcs11h_slotevent_terminate (void) {
	
	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_terminate entry"
	);

	if (g_pkcs11h_data->slotevent.initialized) {
		g_pkcs11h_data->slotevent.should_terminate = TRUE;

		_pkcs11h_slotevent_notify ();

		if (g_pkcs11h_data->slotevent.thread != PKCS11H_THREAD_NULL) {
			_pkcs11h_threading_threadJoin (&g_pkcs11h_data->slotevent.thread);
		}

		_pkcs11h_slotevent_terminate_force ();
	}

	PKCS11H_DEBUG (
		PKCS11H_LOG_DEBUG2,
		"PKCS#11: _pkcs11h_slotevent_terminate return"
	);

	return CKR_OK;
}

#endif
