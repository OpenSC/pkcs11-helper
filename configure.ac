#
# Copyright (c) 2005-2018 Alon Bar-Lev <alon.barlev@gmail.com>
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
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#     o Neither the name of the Alon Bar-Lev nor the names of its
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

AC_PREREQ([2.60])

define([PACKAGE_VERSION_MAJOR], [1])
define([PACKAGE_VERSION_MINOR], [31])
define([PACKAGE_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [_master])

AC_INIT([pkcs11-helper],[PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([lib/common.h])
AM_INIT_AUTOMAKE

PKCS11H_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
PKCS11H_VERSION_MINOR="$(echo PACKAGE_VERSION_MINOR | sed 's/^0*//')"
PKCS11H_VERSION_FIX="PACKAGE_VERSION_FIX"

AC_SUBST([PKCS11H_VERSION_MAJOR])
AC_SUBST([PKCS11H_VERSION_MINOR])
AC_SUBST([PKCS11H_VERSION_FIX])

LIBPKCS11_HELPER_LT_CURRENT="1"
LIBPKCS11_HELPER_LT_OLDEST="1"
LIBPKCS11_HELPER_LT_REVISION="0"
LIBPKCS11_HELPER_LT_AGE="$((${LIBPKCS11_HELPER_LT_CURRENT}-${LIBPKCS11_HELPER_LT_OLDEST}))"

AC_CANONICAL_HOST

AC_ARG_WITH(
	[cygwin-native],
	[AS_HELP_STRING([--with-cygwin-native],[compile native win32])],
	,
	[with_cygwin_native="no"]
)

test -z "${WIN32}" && WIN32="no"
test -z "${CYGWIN}" && CYGWIN="no"
case "${host}" in
 	*-mingw*|*-winnt*)
		WIN32="yes"
		WIN_LIBPREFIX="lib"
	;;
	*-cygwin*)
		AC_MSG_CHECKING([cygwin mode to use])
		CYGWIN="yes"
		if test "${with_cygwin_native}" = "yes"; then
			AC_MSG_RESULT([Using native win32])
			CFLAGS="${CFLAGS} -mno-cygwin"
			WIN32="yes"
		else
			AC_MSG_RESULT([Using cygwin])
			WIN_LIBPREFIX="cyg"
			AC_DEFINE([PKCS11H_USE_CYGWIN], [1], [Define if you are on Cygwin])
		fi
	;;
	*)
	;;
esac

AC_ARG_ENABLE(
	[doc],
	[AS_HELP_STRING([--enable-doc],[enable documentation])],
	,
	[enable_doc="no"]
)

AC_ARG_ENABLE(
	[debug],
	[AS_HELP_STRING([--disable-debug],[disable debug support])],
	,
	[enable_debug="yes"]
)

AC_ARG_ENABLE(
	[threading],
	[AS_HELP_STRING([--disable-threading],[disable threading])],
	,
	[enable_threading="yes"]
)

AC_ARG_ENABLE(
	[token],
	[AS_HELP_STRING([--disable-token],[disable token support])],
	,
	[enable_token="yes"]
)

AC_ARG_ENABLE(
	[data],
	[AS_HELP_STRING([--disable-data],[disable data objects support])],
	,
	[enable_data="yes"]
)

AC_ARG_ENABLE(
	[certificate],
	[AS_HELP_STRING([--disable-certificate],[disable certificate support])],
	,
	[enable_certificate="yes"]
)

AC_ARG_ENABLE(
	[slotevent],
	[AS_HELP_STRING([--disable-slotevent],[disable slotevent support])],
	,
	[enable_slotevent="yes"]
)

AC_ARG_ENABLE(
	[openssl],
	[AS_HELP_STRING([--disable-openssl],[disable openssl interface])],
	,
	[enable_openssl="yes"]
)

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict],[enable strict compiler warnings])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compiler warnings])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[crypto-engine-openssl],
	[AS_HELP_STRING([--disable-crypto-engine-openssl],[disable OpenSSL crypto engine)])],
	,
	[enable_crypto_engine_openssl="yes"]
)

AC_ARG_ENABLE(
	[crypto-engine-gnutls],
	[AS_HELP_STRING([--disable-crypto-engine-gnutls],[disable GnuTLS crypto engine])],
	,
	[enable_crypto_engine_gnutls="yes"]
)

AC_ARG_ENABLE(
	[crypto-engine-nss],
	[AS_HELP_STRING([--disable-crypto-engine-nss],[disable NSS crypto engine])],
	,
	[enable_crypto_engine_nss="yes"]
)

AC_ARG_ENABLE(
	[crypto-engine-polarssl],
	[AS_HELP_STRING([--disable-crypto-engine-polarssl],[disable mbed TLS crypto engine])],
	,
	[enable_crypto_engine_polarssl="yes"]
)

AC_ARG_ENABLE(
	[crypto-engine-mbedtls],
	[AS_HELP_STRING([--disable-crypto-engine-mbedtls],[disable mbed TLS crypto engine])],
	,
	[enable_crypto_engine_mbedtls="${enable_crypto_engine_polarssl}"]
)

AC_ARG_ENABLE(
	[crypto-engine-cryptoapi],
	[AS_HELP_STRING([--disable-crypto-engine-cryptoapi],[disable cryptoapi native crypto engine on windows systems])],
	,
	[enable_crypto_engine_cryptoapi="yes"]
)

AC_ARG_ENABLE(
	[tests],
	[AS_HELP_STRING([--enable-tests],[enable tests])],
	,
	[enable_tests="no"]
)

AC_ARG_WITH(
	[apidocdir],
	[AS_HELP_STRING([--with-apidocdir],[put API documents at this directory, default HTMLDIR/api])],
	[apidocdir="${with_apidocdir}"],
	[apidocdir="\$(htmldir)/api"]
)

AC_ARG_WITH(
	[test-provider],
	[AS_HELP_STRING([--with-test-provider=lib],[specify providers for test phase])],
	[AC_DEFINE_UNQUOTED([TEST_PROVIDER], ["${withval}"], [Test provider])],
	[AC_DEFINE_UNQUOTED([TEST_PROVIDER], ["/usr/lib/pkcs11/provider.so"], [Test provider])]
)

AC_ARG_WITH(
	[test-log-level],
	[AS_HELP_STRING([--with-test-log-level=level],[specify log level for test phase])],
	[AC_DEFINE_UNQUOTED([TEST_LOG_LEVEL], [${withval}], [Test log level])],
	[AC_DEFINE_UNQUOTED([TEST_LOG_LEVEL], [3], [Test log level])]
)

AC_PROG_EGREP
AC_PROG_CC
AC_PROG_INSTALL
PKG_PROG_PKG_CONFIG
AC_ARG_VAR([M4], [m4 utility])
AC_CHECK_PROGS([M4], [m4])

ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
		LT_LANG([Windows Resource])
	],
	[
		AC_LIBTOOL_WIN32_DLL
		AC_LIBTOOL_RC
		AC_PROG_LIBTOOL
	]
)


if test "${enable_doc}" = "yes"; then
	AC_ARG_VAR([DOXYGEN], [doxygen utility])
	AC_CHECK_PROGS([DOXYGEN], [doxygen])
	test -z "${DOXYGEN}" && AC_MSG_ERROR([doxygen is required for docs])
fi

if test "${WIN32}" = "yes"; then
	AC_ARG_VAR([MAN2HTML], [man2html utility])
	AC_CHECK_PROGS([MAN2HTML], [man2html])
	test -z "${MAN2HTML}" && AC_MSG_ERROR([man2html is required for win32])
fi

AC_FUNC_MKTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([ \
	gettimeofday memmove memset socket strchr strdup strerror strrchr \
	snprintf \
])

# Checks for libraries.
AC_CHECK_LIB([dl], [dlopen])

if test "${enable_threading}" = "yes" -a "${WIN32}" != "yes"; then
	AC_CHECK_LIB([pthread], [pthread_create])
fi

PKG_CHECK_MODULES([OPENSSL], [libcrypto >= 0.9.7], [have_openssl="yes"], [have_openssl="no"])
if test "${have_openssl}" = "no"; then
	PKG_CHECK_MODULES([OPENSSL], [openssl >= 0.9.7], [have_openssl="yes"], [have_openssl="no"])
fi

if test "${have_openssl}" = "yes"; then
	old_CFLAGS="${CFLAGS}"
	old_LIBS="${LIBS}"
	CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
	LIBS="${LIBS} ${OPENSSL_LIBS}"
	AC_CHECK_FUNCS([ \
		RSA_meth_dup RSA_meth_free \
		RSA_meth_set_priv_enc RSA_meth_set_priv_dec \
		RSA_meth_set1_name RSA_meth_set_flags \
		DSA_meth_dup DSA_meth_free \
		DSA_meth_set_sign DSA_meth_set1_name DSA_SIG_set0 ECDSA_SIG_set0 \
		EC_KEY_METHOD_get_sign EC_KEY_METHOD_set_sign \
		X509_get0_notBefore X509_get0_notAfter \
	])
	AC_CHECK_FUNC(
		[EC_KEY_METHOD_new],
		[
			openssl_ec="yes"
			AC_DEFINE([ENABLE_PKCS11H_OPENSSL_EC], [1], [Enable openssl EC])
		],
		[AC_CHECK_FUNC(
			[ECDSA_METHOD_new],
			[
				openssl_ec="yes"
				AC_DEFINE([ENABLE_PKCS11H_OPENSSL_EC], [1], [Enable openssl EC])
			],
			[
				openssl_ec="hack"
				old_CFLAGS="${CFLAGS}"
				old_CPPFLAGS="${CPPFLAGS}"
				CPPFLAGS="${CPPFLAGS} -I."
				CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
				AC_CHECK_HEADER(
					[ecs_locl.h],
					[
						AC_DEFINE([ENABLE_PKCS11H_OPENSSL_EC], [1], [Enable openssl EC])
						AC_DEFINE([ENABLE_PKCS11H_OPENSSL_EC_HACK], [1], [Enable openssl EC])
					],
					[openssl_ec="none"]
				)
				CPPFLAGS="${old_CPPFLAGS}"
				CFLAGS="${old_CFLAGS}"
			],
		)]
	)
	AC_MSG_CHECKING([for OpenSSL ec support])
	AC_MSG_RESULT([${openssl_ec}])
	# https://github.com/OpenSC/pkcs11-helper/pull/55
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM(
			[[#include <openssl/dsa.h>]],
			[[
				int foo() {
					DSA_METHOD *meth = NULL;
					sizeof(meth->name);
				}
			]]
		)],
		[AC_DEFINE([HAVE_DSA_METHOD_NAME], [1], [Have DSA_METHOD->name])]
	)
	CFLAGS="${old_CFLAGS}"
	LIBS="${old_LIBS}"
fi

PKG_CHECK_MODULES([GNUTLS], [gnutls >= 1.4], [have_gnutls="yes"], [have_gnutls="no"])
PKG_CHECK_MODULES([NSS], [nss >= 3.11], [have_nss="yes"], [have_nss="no"])

AC_ARG_VAR([MBEDTLS_CFLAGS], [C compiler flags for mbed TLS])
AC_ARG_VAR([MBEDTLS_LIBS], [linker flags for mbed TLS])
if test -z "${MBEDTLS_LIBS}"; then
	AC_CHECK_LIB(
		[mbedtls],
		[mbedtls_x509_crt_init],
		[
			AC_CHECK_HEADERS(
				[mbedtls/x509_crt.h],
				,
				[AC_MSG_ERROR([Cannot find mbed TLS headers])]
			)
			MBEDTLS_LIBS="-lmbedtls -lmbedx509 -lmbedcrypto"
			have_mbedtls="yes"
		],
		[AC_CHECK_LIB(
			[polarssl],
			[x509_crt_parse],
			[
				AC_CHECK_HEADERS(
					[polarssl/x509_crt.h],
					,
					[AC_MSG_ERROR([Cannot find PolarSSL headers])]
				)
				MBEDTLS_LIBS="-lpolarssl"
				have_mbedtls="yes"
			],
			[have_mbedtls="no"]
		)],
		[-lmbedx509 -lmbedcrypto]
	)
else
	have_mbedtls="yes"
fi

if test -n "${MBEDTLS_CFLAGS}" -a "${have_mbedtls}" = "yes"; then
	old_CFLAGS="${CFLAGS}"
	CFLAGS="${CFLAGS} ${MBEDTLS_CFLAGS}"
	AC_CHECK_HEADERS([mbedtls/x509_crt.h])
	AC_CHECK_HEADERS([polarssl/x509_crt.h])
	CFLAGS="${old_CFLAGS}"
fi

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes"
	CFLAGS="${CFLAGS} -ansi -pedantic -D__STRICT_ANSI__ -D_ISOC99_SOURCE -D_DEFAULT_SOURCE"
fi

if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra -Wpointer-arith -Wsign-compare -Wno-unused-parameter -Wno-unused-function -Wno-variadic-macros -Wno-long-long"
fi

AX_CPP_VARARG_MACRO_ISO
AX_CPP_VARARG_MACRO_GCC
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

AC_STRUCT_TM
AX_SIZE_T_PRINTF
AC_CHECK_INCLUDES_DEFAULT
AC_CHECK_HEADERS([ \
	stdio.h \
	stdlib.h \
	stdargs.h \
	malloc.h \
	ctype.h \
	string.h \
	errno.h \
	assert.h \
	time.h \
])
if test "${WIN32}" != "yes"; then
	AC_CHECK_HEADERS([ \
		signal.h \
		dlfcn.h \
		unistd.h \
		sys/time.h \
		pthread.h \
	])
fi

PKCS11H_FEATURES=" key_prompt"

AC_MSG_CHECKING([OpenSSL interface])
if test "${enable_openssl}" = "yes"; then
	if test "${have_openssl}" != "yes"; then
		AC_MSG_ERROR([OpenSSL enabled but cannot be found])
	fi
	AC_MSG_RESULT([yes])
	CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
	LIBS="${LIBS} ${OPENSSL_LIBS}"
	AC_DEFINE([ENABLE_PKCS11H_OPENSSL], [1], [Enable openssl interface])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} openssl"
else
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([Win32 crypto engine])
if test "${WIN32}" = "yes" -a "${enable_crypto_engine_cryptoapi}" = "yes"; then
	AC_MSG_RESULT([yes])
	AC_DEFINE([ENABLE_PKCS11H_ENGINE_CRYPTOAPI], [1], [Enable cryptoapi crypto engine])
	crypto_engine=1
	PKCS11H_FEATURES="${PKCS11H_FEATURES} engine_crypto_cryptoapi"
else
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([OpenSSL crypto engine])
if test "${enable_crypto_engine_openssl}" = "yes"; then
	if test "${have_openssl}" = "yes"; then
		AC_MSG_RESULT([yes])
		AC_DEFINE([ENABLE_PKCS11H_ENGINE_OPENSSL], [1], [Enable OpenSSL crypto engine])

		# don't add this twice
		if test "${enable_openssl}" != "yes"; then
			CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
			LIBS="${LIBS} ${OPENSSL_LIBS}"
		fi
		crypto_engine=1
		PKCS11H_FEATURES="${PKCS11H_FEATURES} engine_crypto_openssl"
	else
		AC_MSG_RESULT([no])
	fi
else
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([GnuTLS crypto engine])
if test "${enable_crypto_engine_gnutls}" = "yes"; then
	if test "${have_gnutls}" = "yes"; then
		AC_MSG_RESULT([yes])
		AC_DEFINE([ENABLE_PKCS11H_ENGINE_GNUTLS], [1], [Enable GnuTLS crypto engine])
		CFLAGS="${CFLAGS} ${GNUTLS_CFLAGS}"
		LIBS="${LIBS} ${GNUTLS_LIBS}"
		crypto_engine=1
		PKCS11H_FEATURES="${PKCS11H_FEATURES} engine_crypto_gnutls"
	else
		AC_MSG_RESULT([no])
	fi
else
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([NSS crypto engine])
if test "${enable_crypto_engine_nss}" = "yes"; then
	if test "${have_nss}" = "yes"; then
		AC_MSG_RESULT([yes])
		AC_DEFINE([ENABLE_PKCS11H_ENGINE_NSS], [1], [Enable NSS crypto engine])
		CFLAGS="${CFLAGS} ${NSS_CFLAGS}"
		LIBS="${LIBS} ${NSS_LIBS}"
		crypto_engine=1
		PKCS11H_FEATURES="${PKCS11H_FEATURES} engine_crypto_nss"
	else
		AC_MSG_RESULT([no])
	fi
else
	AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([mbed TLS crypto engine])
if test "${enable_crypto_engine_mbedtls}" = "yes"; then
	if test "${have_mbedtls}" = "yes"; then
		AC_MSG_RESULT([yes])
		AC_DEFINE([ENABLE_PKCS11H_ENGINE_MBEDTLS], [1], [Enable mbed TLS crypto engine])
		CFLAGS="${CFLAGS} ${MBEDTLS_CFLAGS}"
		LIBS="${LIBS} ${MBEDTLS_LIBS}"
		crypto_engine=1
		PKCS11H_FEATURES="${PKCS11H_FEATURES} engine_crypto_mbedtls"
	else
		AC_MSG_RESULT([no])
	fi
else
	AC_MSG_RESULT([no])
fi

if test "${enable_threading}" != "yes" -a "${enable_slotevent}" = "yes"; then
	AC_MSG_ERROR([Threading must be enabled for slotevent to be enabled])
fi

if test "${enable_openssl}" = "yes" -a "${enable_certificate}" != "yes"; then
	AC_MSG_ERROR([OpenSSL interface requires certificate interface])
fi

if test "${enable_debug}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_DEBUG], [1], [Enable debug support])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} debug"
fi
if test "${enable_threading}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_THREADING], [1], [Enable threading])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} threading"
fi
if test "${enable_token}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_TOKEN], [1], [Enable token interface])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} token"
fi
if test "${enable_data}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_DATA], [1], [Enable data interface])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} data"
fi
if test "${enable_certificate}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_CERTIFICATE], [1], [Enable certificate interface])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} certificate"
fi
if test "${enable_slotevent}" = "yes"; then
	AC_DEFINE([ENABLE_PKCS11H_SLOTEVENT], [1], [Enable slotevent interface])
	PKCS11H_FEATURES="${PKCS11H_FEATURES} slotevent"
fi
if test -n "${crypto_engine}"; then
	PKCS11H_FEATURES="${PKCS11H_FEATURES} engine_crypto"
fi

PKCS11H_FEATURES="${PKCS11H_FEATURES} " # add trailing space

pkgconfigdir="\$(libdir)/pkgconfig"
m4dir="\$(datadir)/aclocal"
pkcs11hincludedir="\$(includedir)/pkcs11-helper-1.0"
AC_SUBST([apidocdir])
AC_SUBST([pkgconfigdir])
AC_SUBST([m4dir])
AC_SUBST([pkcs11hincludedir])
AC_SUBST([LIBPKCS11_HELPER_LT_CURRENT])
AC_SUBST([LIBPKCS11_HELPER_LT_REVISION])
AC_SUBST([LIBPKCS11_HELPER_LT_AGE])
AC_SUBST([LIBPKCS11_HELPER_LT_OLDEST])
AC_SUBST([WIN_LIBPREFIX])
AC_SUBST([PKCS11H_FEATURES])
AM_CONDITIONAL([ENABLE_SHARED], [test "${enable_shared}" = "yes" ])
AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([CYGWIN], [test "${CYGWIN}" = "yes"])
AM_CONDITIONAL([ENABLE_DOC], [test "${enable_doc}" = "yes"])
AM_CONDITIONAL([ENABLE_PKCS11H_TOKEN], [test "${enable_token}" = "yes"])
AM_CONDITIONAL([ENABLE_PKCS11H_DATA], [test "${enable_data}" = "yes"])
AM_CONDITIONAL([ENABLE_PKCS11H_CERTIFICATE], [test "${enable_certificate}" = "yes"])
AM_CONDITIONAL([ENABLE_PKCS11H_SLOTEVENT], [test "${enable_slotevent}" = "yes"])
AM_CONDITIONAL([ENABLE_PKCS11H_OPENSSL], [test "${enable_openssl}" = "yes"])
AM_CONDITIONAL([ENABLE_TESTS], [test "${enable_tests}" = "yes"])
AC_CONFIG_FILES([
	Makefile
	config-w32-vc.h
	include/Makefile
	include/pkcs11-helper-1.0/Makefile
	include/pkcs11-helper-1.0/pkcs11h-version.h
	man/Makefile
	doc/Makefile
	doc/api/Makefile
	doc/api/Doxyfile
	lib/Makefile
	lib/libpkcs11-helper-1.pc
	lib/versioninfo.rc
	m4dir/Makefile
	distro/Makefile
	distro/rpm/Makefile
	distro/rpm/pkcs11-helper.spec
	distro/debian/Makefile
	tests/Makefile
	tests/test-basic/Makefile
	tests/test-certificate/Makefile
	tests/test-fork/Makefile
	tests/test-openssl/Makefile
	tests/test-slotevent/Makefile
])
AC_OUTPUT
