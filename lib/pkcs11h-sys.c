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
 *  along with this program (see the file COPYING[.GPL2] included with this
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
#include <time.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#include <pkcs11-helper-1.0/pkcs11h-core.h>
#include "_pkcs11h-sys.h"

static
time_t
__mytime (void) {
	return time (NULL);
}

static
void
__mysleep (const unsigned long usec) {
#if defined(_WIN32)
	Sleep (usec/1000);
#else
	usleep (usec);
#endif
}

#if !defined(_WIN32)
static
int
__mygettimeofday (struct timeval *tv) {
	return gettimeofday (tv, NULL);
}
#endif

pkcs11h_engine_system_t g_pkcs11h_sys_engine = {
	malloc,
	free,
	__mytime,
	__mysleep,
#if defined(_WIN32)
	NULL
#else
	__mygettimeofday
#endif
};

CK_RV
pkcs11h_engine_setSystem (
	IN const pkcs11h_engine_system_t * const engine
) {
	PKCS11H_ASSERT (engine!=NULL);

	memmove (&g_pkcs11h_sys_engine, engine, sizeof (pkcs11h_engine_system_t));

	return CKR_OK;
}

