dnl Process this file with autoconf to produce a configure script
AC_INIT([osmo-bsc],
	m4_esyscmd([./git-version-gen .tarball-version]),
	[openbsc@lists.osmocom.org])

dnl *This* is the root dir, even if an install-sh exists in ../ or ../../
AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([dist-bzip2])
AC_CONFIG_TESTDIR(tests)

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl include release helper
RELMAKE='-include osmo-release.mk'
AC_SUBST([RELMAKE])

dnl checks for programs
AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
LT_INIT

dnl check for pkg-config (explained in detail in libosmocore/configure.ac)
AC_PATH_PROG(PKG_CONFIG_INSTALLED, pkg-config, no)
if test "x$PKG_CONFIG_INSTALLED" = "xno"; then
        AC_MSG_WARN([You need to install pkg-config])
fi
PKG_PROG_PKG_CONFIG([0.20])

dnl check for AX_CHECK_COMPILE_FLAG
m4_ifdef([AX_CHECK_COMPILE_FLAG], [], [
	AC_MSG_ERROR([Please install autoconf-archive; re-run 'autoreconf -fi' for it to take effect.])
	])

dnl checks for libraries
AC_SEARCH_LIBS([dlopen], [dl dld], [LIBRARY_DL="$LIBS";LIBS=""])
AC_SUBST(LIBRARY_DL)


PKG_CHECK_MODULES(LIBOSMOCORE, libosmocore >= 0.11.0)
PKG_CHECK_MODULES(LIBOSMOVTY, libosmovty >= 0.11.0)
PKG_CHECK_MODULES(LIBOSMOCTRL, libosmoctrl >= 0.11.0)
PKG_CHECK_MODULES(LIBOSMOGSM, libosmogsm >= 0.11.0)
PKG_CHECK_MODULES(LIBOSMOABIS, libosmoabis >= 0.5.0)
PKG_CHECK_MODULES(LIBOSMONETIF, libosmo-netif >= 0.2.0)
PKG_CHECK_MODULES(LIBOSMOSIGTRAN, libosmo-sigtran >= 0.9.0)
PKG_CHECK_MODULES(LIBOSMOSCCP, libosmo-sccp >= 0.9.0)
PKG_CHECK_MODULES(LIBOSMOMGCPCLIENT, libosmo-mgcp-client >= 1.3.0)

dnl checks for header files
AC_HEADER_STDC

found_pcap=yes
AC_CHECK_HEADERS(pcap/pcap.h,,found_pcap=no)
AM_CONDITIONAL(HAVE_PCAP, test "$found_pcap" = yes)

found_cdk=yes
AC_CHECK_HEADERS(cdk/cdk.h,,found_cdk=no)
AM_CONDITIONAL(HAVE_LIBCDK, test "$found_cdk" = yes)

found_sqlite3=yes
PKG_CHECK_MODULES(SQLITE3, sqlite3, ,found_sqlite3=no)
AM_CONDITIONAL(HAVE_SQLITE3, test "$found_sqlite3" = yes)
AC_SUBST(found_sqlite3)


dnl Checks for typedefs, structures and compiler characteristics

AC_ARG_ENABLE(sanitize,
	[AS_HELP_STRING(
		[--enable-sanitize],
		[Compile with address sanitizer enabled],
	)],
	[sanitize=$enableval], [sanitize="no"])
if test x"$sanitize" = x"yes"
then
	CFLAGS="$CFLAGS -fsanitize=address -fsanitize=undefined"
	CPPFLAGS="$CPPFLAGS -fsanitize=address -fsanitize=undefined"
fi

AC_ARG_ENABLE(werror,
	[AS_HELP_STRING(
		[--enable-werror],
		[Turn all compiler warnings into errors, with exceptions:
		 a) deprecation (allow upstream to mark deprecation without breaking builds);
		 b) "#warning" pragmas (allow to remind ourselves of errors without breaking builds)
		]
	)],
	[werror=$enableval], [werror="no"])
if test x"$werror" = x"yes"
then
	WERROR_FLAGS="-Werror"
	WERROR_FLAGS+=" -Wno-error=deprecated -Wno-error=deprecated-declarations"
	WERROR_FLAGS+=" -Wno-error=cpp" # "#warning"
	CFLAGS="$CFLAGS $WERROR_FLAGS"
	CPPFLAGS="$CPPFLAGS $WERROR_FLAGS"
fi

# The following test is taken from WebKit's webkit.m4
saved_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -fvisibility=hidden "
AC_MSG_CHECKING([if ${CC} supports -fvisibility=hidden])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([char foo;])],
      [ AC_MSG_RESULT([yes])
        SYMBOL_VISIBILITY="-fvisibility=hidden"],
        AC_MSG_RESULT([no]))
CFLAGS="$saved_CFLAGS"
AC_SUBST(SYMBOL_VISIBILITY)

AX_CHECK_COMPILE_FLAG([-Werror=implicit], [CFLAGS="$CFLAGS -Werror=implicit"])
AX_CHECK_COMPILE_FLAG([-Werror=maybe-uninitialized], [CFLAGS="$CFLAGS -Werror=maybe-uninitialized"])
AX_CHECK_COMPILE_FLAG([-Werror=memset-transposed-args], [CFLAGS="$CFLAGS -Werror=memset-transposed-args"])
AX_CHECK_COMPILE_FLAG([-Werror=null-dereference], [CFLAGS="$CFLAGS -Werror=null-dereference"])
AX_CHECK_COMPILE_FLAG([-Werror=sizeof-array-argument], [CFLAGS="$CFLAGS -Werror=sizeof-array-argument"])
AX_CHECK_COMPILE_FLAG([-Werror=sizeof-pointer-memaccess], [CFLAGS="$CFLAGS -Werror=sizeof-pointer-memaccess"])

# Coverage build taken from WebKit's configure.in
AC_MSG_CHECKING([whether to enable code coverage support])
AC_ARG_ENABLE(coverage,
              AC_HELP_STRING([--enable-coverage],
                             [enable code coverage support [default=no]]),
              [],[enable_coverage="no"])
AC_MSG_RESULT([$enable_coverage])
if test "$enable_coverage" = "yes"; then
   COVERAGE_CFLAGS="-ftest-coverage -fprofile-arcs"
   COVERAGE_LDFLAGS="-ftest-coverage -fprofile-arcs"
   AC_SUBST([COVERAGE_CFLAGS])
   AC_SUBST([COVERAGE_LDFLAGS])
fi

AC_ARG_ENABLE(profile,
		[AS_HELP_STRING([--enable-profile], [Compile with profiling support enabled], )],
		[profile=$enableval], [profile="no"])
if test x"$profile" = x"yes"
then
	CFLAGS="$CFLAGS -pg"
	CPPFLAGS="$CPPFLAGS -pg"
fi

AC_ARG_ENABLE([external_tests],
		AC_HELP_STRING([--enable-external-tests],
				[Include the VTY/CTRL tests in make check [default=no]]),
		[enable_ext_tests="$enableval"],[enable_ext_tests="no"])
if test "x$enable_ext_tests" = "xyes" ; then
	AC_CHECK_PROG(PYTHON2_AVAIL,python2,yes)
	 if test "x$PYTHON2_AVAIL" != "xyes" ; then
		AC_MSG_ERROR([Please install python2 to run the VTY/CTRL tests.])
	fi
	AC_CHECK_PROG(OSMOTESTEXT_CHECK,osmotestvty.py,yes)
	 if test "x$OSMOTESTEXT_CHECK" != "xyes" ; then
		AC_MSG_ERROR([Please install git://osmocom.org/python/osmo-python-tests to run the VTY/CTRL tests.])
	fi
fi
AC_MSG_CHECKING([whether to enable VTY/CTRL tests])
AC_MSG_RESULT([$enable_ext_tests])
AM_CONDITIONAL(ENABLE_EXT_TESTS, test "x$enable_ext_tests" = "xyes")

AC_MSG_RESULT([CFLAGS="$CFLAGS"])
AC_MSG_RESULT([CPPFLAGS="$CPPFLAGS"])

dnl Generate the output
AM_CONFIG_HEADER(bscconfig.h)

AC_OUTPUT(
    include/Makefile
    include/osmocom/Makefile
    include/osmocom/bsc/Makefile
    src/Makefile
    src/libbsc/Makefile
    src/libfilter/Makefile
    src/osmo-bsc/Makefile
    src/ipaccess/Makefile
    src/utils/Makefile
    tests/Makefile
    tests/atlocal
    tests/gsm0408/Makefile
    tests/bsc/Makefile
    tests/abis/Makefile
    tests/subscr/Makefile
    tests/nanobts_omlattr/Makefile
    tests/handover/Makefile
    doc/Makefile
    doc/examples/Makefile
    Makefile)
