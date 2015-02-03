# configure.ac - for adns
# Copyright (C) 2008 g10 Code GmbH
#
# This file is part of adns, which is
#    Copyright (C) 1997-2000,2003,2006  Ian Jackson
#    Copyright (C) 1999-2000,2003,2006  Tony Finch
#    Copyright (C) 1991 Massachusetts Institute of Technology
#  (See the file INSTALL for full details.)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.61)
min_automake_version="1.14"

# To build a release you need to create a tag with the version number
# (git tag -s gnupg-2.n.m) and run "./autogen.sh --force".  Please
# bump the version number immediately *after* the release and do
# another commit and push so that the git magic is able to work.
# See below for the LT version numbers.
m4_define([mym4_version], [1.4-g10-6])

# Below is m4 magic to extract and compute the git revision number,
# the decimalized short revision number, a beta version string and a
# flag indicating a development version (mym4_isgit).  Note that the
# m4 processing is done by autoconf and not during the configure run.
m4_define([mym4_revision], m4_esyscmd([git branch -v 2>/dev/null \
          | awk '/^\* / {printf "%s",$3}']))
m4_define([mym4_revision_dec],
          m4_esyscmd_s([echo $((0x$(echo ]mym4_revision[|head -c 4)))]))
m4_define([mym4_betastring],
          m4_esyscmd_s([git describe --match 'adns-1.4-g10-*[0-9]' --long|\
                        awk -F- '$5!=0{print"-beta"$5}']))
m4_define([mym4_isgit],m4_if(mym4_betastring,[],[no],[yes]))
m4_define([mym4_full_version],[mym4_version[]mym4_betastring])

AC_INIT([adns], [mym4_full_version], [bug-adns@g10code.com])

# LT Version numbers: Remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
# Please remember to document interface changes in the NEWS file.
ADNS_LT_CURRENT=4
ADNS_LT_AGE=3
ADNS_LT_REVISION=2

# If the API is changed in an incompatible way: increment this counter.
ADNS_CONFIG_API_VERSION=1


AC_CONFIG_SRCDIR([src/adns.h])
AM_INIT_AUTOMAKE([serial-tests dist-bzip2 no-dist-gzip])
AM_MAINTAINER_MODE
AM_CONFIG_HEADER(src/config.h)
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST
AC_GNU_SOURCE


AC_SUBST(ADNS_LT_CURRENT)
AC_SUBST(ADNS_LT_AGE)
AC_SUBST(ADNS_LT_REVISION)
AC_DEFINE_UNQUOTED(ADNS_VERSION_STRING, "$VERSION", [Version of this library])

# Checks for programs.
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
if test "x$ac_cv_prog_cc_c89" = "xno" ; then
  AC_MSG_ERROR([[No C-89 compiler found]])
fi
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_CHECK_PROGS(M4, m4)
AC_C_INLINE
AC_LANG([C])

#
# Libtool stuff
#
LT_PREREQ([2.2.6])
LT_INIT([win32-dll disable-static])
LT_LANG([Windows Resource])


# This is handy for debugging so the compiler doesn't rearrange
# things and eliminate variables.
AC_ARG_ENABLE(optimization,
       AC_HELP_STRING([--disable-optimization],
		      [disable compiler optimization]),
                      [if test $enableval = no ; then
                         CFLAGS=`echo $CFLAGS | sed 's/-O[[0-9]]//'`
                       fi])

if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wstrict-prototypes"
    CLFAGS="$CLFAGS -Wmissing-prototypes -Wwrite-strings -Wcast-qual"

    AC_MSG_CHECKING([if gcc supports -Wpointer-arith])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_psign=yes,_gcc_psign=no)
    AC_MSG_RESULT($_gcc_psign)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wpointer-arith"
    fi

    AC_MSG_CHECKING([if gcc supports -Wno-pointer-sign])
    _gcc_cflags_save=$CFLAGS
    CFLAGS="-Wpointer-arith"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],_gcc_psign=yes,_gcc_psign=no)
    AC_MSG_RESULT($_gcc_psign)
    CFLAGS=$_gcc_cflags_save;
    if test x"$_gcc_psign" = xyes ; then
       CFLAGS="$CFLAGS -Wno-pointer-sign"
    fi
fi

# Setup some stuff depending on host.
have_w32_system=no
use_tsearch=yes
case "${host}" in
    *-*-mingw32*)
      have_w32_system=yes
      # We need to pass HAVE_W32_SYSTEM on the command line because
      # config.h is not always included first but we need to include
      # some header files conditionally.  Note that in the public
      # header file (adns.h) we need to use the _WIN32 macro despite
      # that it is very questionable whether Windows is win.
      PLATFORMCPPFLAGS="-DHAVE_W32_SYSTEM"
      # Newer mingw packages have tsearch but there are other problems
      # when enabling it.  For now disable it.
      use_tsearch=no
      ;;
    *)
      PLATFORMCPPFLAGS=
      ;;
esac
AC_SUBST(PLATFORMCPPFLAGS)
AM_CONDITIONAL(HAVE_W32_SYSTEM, test "$have_w32_system" = yes)


# For some systems we know that we have ld_version scripts.
# Use it then as default.
have_ld_version_script=no
case "${host}" in
    *-*-linux*)
	have_ld_version_script=yes
        ;;
    *-*-gnu*)
	have_ld_version_script=yes
        ;;
esac
AC_ARG_ENABLE([ld-version-script],
              AC_HELP_STRING([--enable-ld-version-script],
                             [enable/disable use of linker version script.
                              (default is system dependent)]),
              [have_ld_version_script=$enableval],
              [ : ] )
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, test "$have_ld_version_script" = "yes")



#
# Checks for libraries.
#


#
# Checks for header files.
#
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST


#
# Checks for library functions.
#
AC_CHECK_FUNCS([poll tsearch gettimeofday])
AM_CONDITIONAL(HAVE_TSEARCH, test "x$ac_cv_func_tsearch" = "xyes"  \
                             -a "x$use_tsearch" = "xyes")

# fixme: we should check for nrand48 and use a replace function if it
# is not there.  src/w32misc.c has such an replacement.


# Fixme: Use a modern autoconf macro.
if test "$have_w32_system" != yes; then
AC_MSG_CHECKING(for INADDR_LOOPBACK)
AC_CACHE_VAL(adns_cv_decl_inaddrloopback,[
 AC_TRY_COMPILE([
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
 ],[
  INADDR_LOOPBACK;
 ],
 adns_cv_decl_inaddrloopback=yes,
 adns_cv_decl_inaddrloopback=no)])
if test "$adns_cv_decl_inaddrloopback" = yes; then
 AC_MSG_RESULT(found)
else
 AC_MSG_RESULT([not in standard headers, urgh...])
 AC_CHECK_HEADER(rpc/types.h,[
  AC_DEFINE(HAVEUSE_RPCTYPES_H, 1,
           [Define if we want to include rpc/types.h.  Crap BSDs put INADDR_LOOPBACK there.])
 ],[
  AC_MSG_ERROR([cannot find INADDR_LOOPBACK or rpc/types.h])
 ])
fi
fi


# Check for required network libraries.
if test "$have_w32_system" = yes; then
  LIBS="$LIBS -lws2_32 -liphlpapi"
else
  AC_SEARCH_LIBS([inet_aton], [resolv])
fi


#
# Stuff required to create adns-config
#
ADNS_CONFIG_LIBS="-ladns"
ADNS_CONFIG_CFLAGS=""
AC_SUBST(ADNS_CONFIG_LIBS)
AC_SUBST(ADNS_CONFIG_CFLAGS)
AC_SUBST(ADNS_CONFIG_API_VERSION)

# The Makefiles need to know about cross compiling
AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)


# Generate extended version information for W32.
if test "$have_w32_system" = yes; then
   BUILD_REVISION=mym4_revision
   BUILD_TIMESTAMP=`date --iso-8601=minutes`
   changequote(,)dnl
   BUILD_FILEVERSION=`echo "$PACKAGE_VERSION" \
                      | sed 's/\([0-9.]*\)-g10-\([0-9]*\).*/\1.\2./;s/\./,/g'`
   changequote([,])dnl
   BUILD_FILEVERSION="${BUILD_FILEVERSION}mym4_revision_dec"
fi
AC_SUBST(BUILD_REVISION)
AC_SUBST(BUILD_TIMESTAMP)
AC_SUBST(BUILD_FILEVERSION)



#
# Stuff which goes at the bottom of config.h.
#
AH_BOTTOM([
/* Use the definitions: */

#ifdef HAVE_POLL
#include <sys/poll.h>
#else
/* kludge it up */
struct pollfd { int fd; short events; short revents; };
#define POLLIN  1
#define POLLPRI 2
#define POLLOUT 4
#endif

#ifdef __GNUC__
# define ADNS_GCC_VERSION (__GNUC__ * 10000 \
                           + __GNUC_MINOR__ * 100 \
                           + __GNUC_PATCHLEVEL__)
#else
# define ADNS_GCC_VERSION 0
#endif

/* GNU C attributes. */
#ifndef FUNCATTR
# if ADNS_GCC_VERSION >= 20500
#  define FUNCATTR(x) __attribute__(x)
# else
#  define FUNCATTR(x)
# endif
#endif

/* GNU C printf formats, or null. */
#ifndef ATTRPRINTF
# if ADNS_GCC_VERSION >= 20500
#  define ATTRPRINTF(si,tc) format (printf,si,tc)
# else
#  define ATTRPRINTF(si,tc)
# endif
#endif
#ifndef PRINTFFORMAT
# define PRINTFFORMAT(si,tc) FUNCATTR((ATTRPRINTF(si,tc)))
#endif


/* GNU C nonreturning functions, or null. */
#ifndef ATTRNORETURN
# if ADNS_GCC_VERSION >= 20500
#  define ATTRNORETURN  noreturn
# else
#  define ATTRNORETURN
# endif
#endif
#ifndef NONRETURNING
#define NONRETURNING FUNCATTR((ATTRNORETURN))
#endif

/* Combination of both the above. */
#ifndef NONRETURNPRINTFFORMAT
#define NONRETURNPRINTFFORMAT(si,tc) FUNCATTR((ATTRPRINTF(si,tc),ATTRNORETURN))
#endif


#ifdef HAVEUSE_RPCTYPES_H
#include <rpc/types.h>
#endif
])


AC_CONFIG_FILES([
Makefile
m4/Makefile
src/Makefile
src/adns-config
src/versioninfo.rc
client/Makefile
regress/Makefile
])
AC_OUTPUT


echo "
        adns v${PACKAGE_VERSION} has been configured as follows:

        Revision:  mym4_revision  (mym4_revision_dec)
        Platform:  $host

"
