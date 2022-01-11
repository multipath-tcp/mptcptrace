AC_INIT([mptcptrace], [m4_esyscmd_s([git describe --abbrev=0 --dirty --always])], [benjamin.hesmans@uclouvain.be])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_MSG_CHECKING([pkg-config])
if test m4_ifdef([PKG_CHECK_MODULES], [yes], [no]) == yes; then
	AC_MSG_RESULT([yes]);
else
	AC_MSG_RESULT([no]);
	AC_MSG_ERROR([You need pkg-config])
fi

AC_DEFINE([USE_HASHTABLE], [1], [Use a hashtable for better scale])
AC_DEFINE([ENDCONN], [1], [Mark connections end])

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])
PKG_CHECK_MODULES([CRYPTO], [libcrypto])
AC_SUBST(CRYPTO_CFLAGS)
AC_SUBST(CRYPTO_LIBS)
AC_CHECK_HEADER([openssl/hmac.h], [], [AC_MSG_ERROR([you need openssl (headers) installed, e.g. libssl-dev package])])
AC_CHECK_HEADER([openssl/sha.h], [], [AC_MSG_ERROR([you need openssl (headers) installed, e.g. libssl-dev package])])
AC_CHECK_HEADER([pcap.h], [], [AC_MSG_ERROR([you need pcap (headers) installed, e.g. libpcap-dev package])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
LT_INIT
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT
