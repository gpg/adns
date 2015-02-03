# src/Makefile.am
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

## Process this file with automake to produce Makefile.in

# Thsi directory.  It is used by the include file.
adnssrcdir = $(top_srcdir)/src

EXTRA_DIST = adns-config.in libadns.vers libadns.def versioninfo.rc.in \
             w32support.c w32extra.c w32inet.c
bin_SCRIPTS = adns-config
include_HEADERS = adns.h
lib_LTLIBRARIES = libadns.la

AM_CPPFLAGS=$(PLATFORMCPPFLAGS)

if HAVE_LD_VERSION_SCRIPT
  adns_version_script_cmd = -Wl,--version-script=$(srcdir)/libadns.vers
else
  adns_version_script_cmd =
endif


if HAVE_W32_SYSTEM
LTRCCOMPILE = $(LIBTOOL) --mode=compile $(RC) \
     `echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) | \
     sed -e 's/-I/--include-dir /g;s/-D/--define /g'`

.rc.lo:
	$(LTRCCOMPILE) -i $< -o $@

adns_res = versioninfo.lo
adns_res_ldflag = -Wl,.libs/versioninfo.o
no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/libadns.def
extra_ltoptions = -XCClinker -static-libgcc
adns_deps = $(ksba_res) libadns.def
w32src = w32support.c w32extra.c w32inet.c

install-def-file:
	$(INSTALL) $(srcdir)/libadns.def $(DESTDIR)$(libdir)/libadns.def

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/libadns.def

else !HAVE_W32_SYSTEM
adns_res =
adns_ldflag =
no_undefined =
export_symbols =
extra_ltoptions =
adns_deps =
w32src =
install-def-file:
uninstall-def-file:
endif !HAVE_W32_SYSTEM


libadns_la_LDFLAGS = $(no_undefined) $(export_symbols) $(extra_ltoptions) \
      $(adns_version_script_cmd) -version-info \
      @ADNS_LT_CURRENT@:@ADNS_LT_REVISION@:@ADNS_LT_AGE@
libadns_la_DEPENDENCIES = $(srcdir)/libadns.vers $(adns_deps)
libadns_la_LIBADD = @LTLIBOBJS@ $(NETLIBS)

# Because we need the list of source files also in ../regress, we put
# them into a separate file.
include $(srcdir)/source.list

libadns_la_SOURCES = $(adnssources) $(w32src)


install-data-local: install-def-file

uninstall-local: uninstall-def-file


