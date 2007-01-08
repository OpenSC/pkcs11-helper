#
# Copyright (c) 2005-2006 Alon Bar-Lev <alon.barlev@gmail.com>
# All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, or the BSD license.
#
# GNU General Public License (GPL) Version 2
# ===========================================
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING.GPL included with this
# distribution); if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# BSD License
# ============
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     o Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     o Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     o Neither the name of the <ORGANIZATION> nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

AC_PREREQ(2.60)
AC_INIT(pkcs11-helper, 1.03-beta1)
AM_INIT_AUTOMAKE(pkcs11-helper, [$PACKAGE_VERSION])
AM_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([lib/common.h])

# Checks for programs.
AC_CANONICAL_HOST

LIBPKCS11_HELPER_LT_CURRENT="1"
LIBPKCS11_HELPER_LT_REVISION="0"
LIBPKCS11_HELPER_LT_AGE="0"
AC_SUBST(LIBPKCS11_HELPER_LT_CURRENT)
AC_SUBST(LIBPKCS11_HELPER_LT_REVISION)
AC_SUBST(LIBPKCS11_HELPER_LT_AGE)

AC_ARG_WITH(cygwin-native,
	[  --with-cygwin-native              Compile native win32],
	[CYGWIN_NATIVE="${withval}"],
	[CYGWIN_NATIVE="no"]
)

WIN32="no"
CYGWIN="no"
case "${host}" in
	*-mingw32*)
		WIN32="yes"
	;;
	*-cygwin*)
		AC_MSG_CHECKING([cygwin mode to use])
		CYGWIN="yes"
		if test "${CYGWIN_NATIVE}" = "yes"; then
			AC_MSG_RESULT([Using native win32])
			CFLAGS="${CFLAGS} -mno-cygwin"
			WIN32="yes"
		else
			AC_MSG_RESULT([Using cygwin])
			AC_DEFINE(PKCS11H_USE_CYGWIN, 1, [Define if you are on Cygwin])
		fi
	;;
	*)
	;;
esac

AC_ARG_ENABLE(doc,
	[  --enable-doc                      Enable documantation],
	[ENABLE_DOC="${enableval}"],
	[ENABLE_DOC="no"]
)

AC_ARG_ENABLE(debug,
	[  --disable-debug                   Disable debug support],
	[ENABLE_PKCS11H_DEBUG="${enableval}"],
	[ENABLE_PKCS11H_DEBUG="yes"]
)

AC_ARG_ENABLE(threading,
	[  --disable-threading               Disable threading],
	[ENABLE_PKCS11H_THREADING="${enableval}"],
	[ENABLE_PKCS11H_THREADING="yes"]
)

AC_ARG_ENABLE(token,
	[  --disable-token                   Disable token support],
	[ENABLE_PKCS11H_TOKEN="${enableval}"],
	[ENABLE_PKCS11H_TOKEN="yes"]
)

AC_ARG_ENABLE(data,
	[  --disable-data                    Disable data objects support],
	[ENABLE_PKCS11H_DATA="${enableval}"],
	[ENABLE_PKCS11H_DATA="yes"]
)

AC_ARG_ENABLE(certificate,
	[  --disable-certificate             Disable certificate support],
	[ENABLE_PKCS11H_CERTIFICATE="${enableval}"],
	[ENABLE_PKCS11H_CERTIFICATE="yes"]
)

AC_ARG_ENABLE(slotevent,
	[  --disable-slotevent               Disable slotevent support],
	[ENABLE_PKCS11H_SLOTEVENT="${enableval}"],
	[ENABLE_PKCS11H_SLOTEVENT="yes"]
)

AC_ARG_ENABLE(openssl,
	[  --disable-openssl                 Disable openssl interface],
	[ENABLE_PKCS11H_OPENSSL="${enableval}"],
	[ENABLE_PKCS11H_OPENSSL="yes"]
)

AC_ARG_ENABLE(pedantic,
	[  --enable-pedantic                 Enable pedantic compiler warnings, will not generate a working executable (debugging option)],
	[PEDANTIC="${enableval}"],
	[PEDANTIC="no"]
)

AC_ARG_WITH(crypto-engine-openssl,
	[  --without-crypto-engine-openssl   Disable OpenSSL crypto engine],
	[WITH_CRYPTO_ENGINE_OPENSSL="${withval}"],
	[WITH_CRYPTO_ENGINE_OPENSSL="yes"]
)

AC_ARG_WITH(crypto-engine-gnutls,
	[  --without-crypto-engine-gnutls    Disable GNUTLS crypto engine (OpenSSL will be used if both enabled)],
	[WITH_CRYPTO_ENGINE_GNUTLS="${withval}"],
	[WITH_CRYPTO_ENGINE_GNUTLS="yes"]
)

AC_ARG_WITH(crypto-engine-win32,
	[  --without-crypto-engine-win32     Disable win32 native crypto engine on win32 systems],
	[WITH_CRYPTO_ENGINE_WIN32="${withval}"],
	[WITH_CRYPTO_ENGINE_WIN32="yes"]
)

AC_ARG_WITH(mem-check,
	[  --with-mem-check=TYPE             Build with debug memory checking, TYPE = valgrind],
	[MEMCHECK="$withval"]
)

AC_ARG_WITH(test-provider,
	[  --with-test-provider=lib          Specify providers for test phase],
	[
		AC_DEFINE_UNQUOTED([TEST_PROVIDER], ["${withval}"], [Test provider])
	],
	[
		AC_DEFINE_UNQUOTED([TEST_PROVIDER], ["/usr/lib/pkcs11/provider.so"], [Test provider])
	]
)

AC_ARG_WITH(test-log-level,
	[  --with-test-log-level=level       Specify log level for test phase],
	[
		AC_DEFINE_UNQUOTED([TEST_LOG_LEVEL], [${withval}], [Test log level])
	],
	[
		AC_DEFINE_UNQUOTED([TEST_LOG_LEVEL], [3], [Test log level])
	]
)

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG
if test "${ENABLE_DOC}" = "yes"; then
	AC_CHECK_PROGS([DOXYGEN], [doxygen])
	test -z "${DOXYGEN}" && AC_MSG_ERROR([doxygen is required for docs])
fi
if test "${WIN32}" = "yes"; then
	AC_CHECK_PROGS([MAN2HTML], [man2html])
	test -z "${MAN2HTML}" && AC_MSG_ERROR([man2html is required for win32])
fi

AC_FUNC_MKTIME
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([ \
	gettimeofday memmove memset socket strchr strdup strerror strrchr \
	snprintf \
])

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])

if test "${ENABLE_PKCS11H_THREADING}" = "yes" -a "${WIN32}" != "yes"; then
	AC_CHECK_LIB([pthread], [pthread_create])
fi

PKG_CHECK_MODULES([OPENSSL], [libcrypto >= 0.9.7], [HAVE_OPENSSL="yes"], [HAVE_OPENSSL="no"])
if test "${HAVE_OPENSSL}" = "no"; then
	PKG_CHECK_MODULES([OPENSSL], [openssl >= 0.9.7], [HAVE_OPENSSL="yes"], [HAVE_OPENSSL="no"])
fi

PKG_CHECK_MODULES([GNUTLS], [gnutls >= 1.4], [HAVE_GNUTLS="yes"], [HAVE_GNUTLS="no"])

AC_MSG_CHECKING([cryptographic library to use])

if test "${WITH_CRYPTO_ENGINE_OPENSSL}" = "yes" -a "${HAVE_OPENSSL}" != "yes"; then
	WITH_CRYPTO_ENGINE_OPENSSL="no"
fi

if test "${WITH_CRYPTO_ENGINE_GNUTLS}" = "yes" -a "${HAVE_GNUTLS}" != "yes"; then
	WITH_CRYPTO_ENGINE_GNUTLS="no"
fi

if test "${WIN32}" = "yes" -a "${WITH_CRYPTO_ENGINE_WIN32}" = "yes"; then
	AC_MSG_RESULT([Using win32])
	AC_DEFINE(ENABLE_PKCS11H_ENGINE_WIN32, 1, [Use win32 crypto engine])

	if test "${ENABLE_PKCS11H_OPENSSL}" = "yes"; then
		CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
		LIBS="${LIBS} ${OPENSSL_LIBS}"
	fi
elif test "${WITH_CRYPTO_ENGINE_OPENSSL}" = "yes"; then
	AC_MSG_RESULT([Using OpenSSL])
	AC_DEFINE(ENABLE_PKCS11H_ENGINE_OPENSSL, 1, [Use OpenSSL crypto engine])
	CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
	LIBS="${LIBS} ${OPENSSL_LIBS}"
elif test "${WITH_CRYPTO_ENGINE_GNUTLS}" = "yes"; then
	AC_MSG_RESULT([Using GNUTLS])
	AC_DEFINE(ENABLE_PKCS11H_ENGINE_GNUTLS, 1, [Use GNUTLS crypto engine])
	CFLAGS="${CFLAGS} ${GNUTLS_CFLAGS}"
	LIBS="${LIBS} ${GNUTLS_LIBS}"
else
	AC_MSG_RESULT([No engine selected.])
fi

# Checks for header files.
AC_HEADER_STDC
AX_CPP_VARARG_MACRO_ISO
AX_CPP_VARARG_MACRO_GCC
AC_C_CONST
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_CHECK_HEADERS([[ \
	stdio.h \
	stdlib.h \
	stdargs.h \
	malloc.h \
	ctype.h \
	string.h \
	errno.h \
	assert.h \
	time.h \
]])
if test "${WIN32}" != "yes"; then
	AC_CHECK_HEADERS([ \
		signal.h \
		dlfcn.h \
		unistd.h \
		sys/time.h \
		pthread.h \
	])
fi

if test "$MEMCHECK" = "valgrind"; then
	AC_CHECKING([for valgrind tool and Header files])
	PKG_CHECK_MODULES([VALGRIND], [valgrind >= 3.0.0], [HAVE_VALGRIND=yes], [HAVE_VALGRIND=no])
	if test "${HAVE_VALGRIND}" != "yes"; then
		AC_MSG_ERROR([valgrind was not found])
	fi
	AC_DEFINE(USE_VALGRIND, 1, [Use valgrind memory debugging library])
	CFLAGS="${CFLAGS} ${VALGRIND_CFLAGS} -g -fno-inline"
#	LIBS="${VALGRIND_LIBS} ${LIBS}"
fi

CFLAGS="$CFLAGS -Wall -Wpointer-arith -Wsign-compare -Wno-unused-parameter -Wno-unused-function"

if test "$PEDANTIC" = "yes"; then
	CFLAGS="${CFLAGS} -ansi -pedantic -D__STRICT_ANSI__ -D_POSIX_SOURCE -D_POSIX_C_SOURCE -D_SVID_SOURCE"
fi

if test "${WIN32}" = "yes"; then
	LIBS="${LIBS} -lkernel32 -lgdi32"
fi

if test "${ENABLE_PKCS11H_THREADING}" != "yes" -a "${ENABLE_PKCS11H_SLOTEVENT}" = "yes"; then
	AC_MSG_ERROR([Threading must be enabled for slotevent to be enabled])
fi

if test "${ENABLE_PKCS11H_OPENSSL}" = "yes" -a "${WITH_CRYPTO_ENGINE_OPENSSL}" != "yes"; then
	AC_MSG_ERROR([OpenSSL must be linked for OpenSSL interface to operate])
fi

if test "${ENABLE_PKCS11H_OPENSSL}" = "yes" -a "${ENABLE_PKCS11H_CERTIFICATE}" != "yes"; then
	AC_MSG_ERROR([OpenSSL interface requires certificate interface])
fi

if test "${ENABLE_PKCS11H_DEBUG}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_DEBUG], 1, [Enable debug support])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} debug"
fi
if test "${ENABLE_PKCS11H_THREADING}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_THREADING], 1, [Enable threading])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} threading"
fi
if test "${ENABLE_PKCS11H_TOKEN}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_TOKEN], 1, [Enable token interface])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} token"
fi
if test "${ENABLE_PKCS11H_DATA}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_DATA], 1, [Enable data interface])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} data"
fi
if test "${ENABLE_PKCS11H_CERTIFICATE}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_CERTIFICATE], 1, [Enable certificate interface])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} certificate"
fi
if test "${ENABLE_PKCS11H_SLOTEVENT}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_SLOTEVENT], 1, [Enable slotevent interface])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} slotevent"
fi
if test "${ENABLE_PKCS11H_OPENSSL}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_OPENSSL], 1, [Enable openssl interface])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} openssl"
fi
if test \
	"${WITH_CRYPTO_ENGINE_OPENSSL}" = "yes" -o \
	"${WITH_CRYPTO_ENGINE_GNUTLS}" = "yes" -o \
	"${WITH_CRYPTO_ENGINE_WIN32}" = "yes"; then
	PKCS11H_FEATURES="${PKCS11H_FEATURES} engine_crypto"
fi

mydocdir="\${docdir}-${PACKAGE_VERSION}"
pkgconfigdir="\${libdir}/pkgconfig"
AC_SUBST([mydocdir])
AC_SUBST([pkgconfigdir])
AC_SUBST([PKCS11H_FEATURES])
AM_CONDITIONAL(ENABLE_DOC, test "${ENABLE_DOC}" = "yes")
AM_CONDITIONAL(WIN32, test "${WIN32}" = "yes")
AM_CONDITIONAL(CYGWIN, test "${CYGWIN}" = "yes")
AM_CONDITIONAL(ENABLE_PKCS11H_TOKEN, test "${ENABLE_PKCS11H_TOKEN}" = "yes")
AM_CONDITIONAL(ENABLE_PKCS11H_DATA, test "${ENABLE_PKCS11H_DATA}" = "yes")
AM_CONDITIONAL(ENABLE_PKCS11H_CERTIFICATE, test "${ENABLE_PKCS11H_CERTIFICATE}" = "yes")
AM_CONDITIONAL(ENABLE_PKCS11H_SLOTEVENT, test "${ENABLE_PKCS11H_SLOTEVENT}" = "yes")
AM_CONDITIONAL(ENABLE_PKCS11H_OPENSSL, test "${ENABLE_PKCS11H_OPENSSL}" = "yes")
AC_CONFIG_FILES([
	Makefile
	config-w32-vc.h
	pkcs11-helper.spec
	include/Makefile
	include/pkcs11-helper-1.0/Makefile
	include/pkcs11-helper-1.0/pkcs11h-version.h
	man/Makefile
	doc/Makefile
	doc/api/Makefile
	lib/Makefile
	lib/libpkcs11-helper-1.pc
	m4dir/Makefile
	tests/Makefile
	tests/test-basic/Makefile
	tests/test-certificate/Makefile
	tests/test-slotevent/Makefile
])
AC_OUTPUT

