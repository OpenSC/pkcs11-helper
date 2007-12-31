dnl @synopsis AX_CPP_VARARG_MACRO_GCC
dnl
dnl Test if the preprocessor understands GNU GCC-style vararg macros.
dnl If it does, defines HAVE_CPP_VARARG_MACRO_GCC to 1.
dnl
dnl @version
dnl @author James Yonan <jim@yonan.net>, Matthias Andree <matthias.andree@web.de>
AC_DEFUN([AX_CPP_VARARG_MACRO_GCC], [dnl
    AS_VAR_PUSHDEF([VAR],[ax_cv_cpp_vararg_macro_gcc])dnl
    AC_CACHE_CHECK([for GNU GCC vararg macro support], VAR, [dnl
      AC_COMPILE_IFELSE([
	#define macro(a, b...) func(a, b)
	int func(int a, int b, int c);
	int test() { return macro(1, 2, 3); }
	], [ VAR=yes ], [VAR=no])])
    if test $VAR = yes ; then
    AC_DEFINE([HAVE_CPP_VARARG_MACRO_GCC], 1, 
      [Define to 1 if your compiler supports GNU GCC-style variadic macros])
    fi
    AS_VAR_POPDEF([VAR])dnl
])

dnl @synopsis AX_CPP_VARARG_MACRO_ISO
dnl
dnl Test if the preprocessor understands ISO C 1999 vararg macros.
dnl If it does, defines HAVE_CPP_VARARG_MACRO_ISO to 1.
dnl
dnl @version
dnl @author James Yonan <jim@yonan.net>, Matthias Andree <matthias.andree@web.de>
AC_DEFUN([AX_CPP_VARARG_MACRO_ISO], [dnl
    AS_VAR_PUSHDEF([VAR],[ax_cv_cpp_vararg_macro_iso])dnl
    AC_CACHE_CHECK([for ISO C 1999 vararg macro support], VAR, [dnl
      AC_COMPILE_IFELSE([
#define macro(a, ...) func(a, __VA_ARGS__)
	int func(int a, int b, int c);
	int test() { return macro(1, 2, 3); }
	], [ VAR=yes ], [VAR=no])])
    if test $VAR = yes ; then
    AC_DEFINE([HAVE_CPP_VARARG_MACRO_ISO], 1, 
      [Define to 1 if your compiler supports ISO C99 variadic macros])
    fi
    AS_VAR_POPDEF([VAR])dnl
])

dnl @synopsis AX_SIZE_T_PRINTF
dnl
dnl Test if %zx is supported by printf.
dnl
dnl @version
dnl @author <alon.barlev@gmail.com>
AC_DEFUN([AX_SIZE_T_PRINTF], [dnl
	AC_TYPE_SIZE_T dnl
	AC_CHECK_SIZEOF([size_t])dnl
	AC_MSG_CHECKING([size_t printf format])
	if test ${ac_cv_sizeof_size_t} = 4; then
		ax_cv_printf_z_format="%08lx"
	else
		ax_cv_printf_z_format="%016lx"
	fi
	AC_MSG_RESULT([${ax_cv_printf_z_format}])dnl
	AC_DEFINE_UNQUOTED(
		[PRINTF_Z_FORMAT],dnl
		["${ax_cv_printf_z_format}"],dnl
		[Define printf format for size_t]dnl
	)dnl
])
