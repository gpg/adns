# Makefile.am - Makefile for client/
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


bin_PROGRAMS = adnslogres adnsheloex adnshost
if HAVE_TSEARCH
bin_PROGRAMS += adnsresfilter
endif

noinst_PROGRAMS = fanftest adnstest

AM_CPPFLAGS = $(PLATFORMCPPFLAGS) -I$(top_srcdir)/src

LDADD = ../src/libadns.la

BUILT_SOURCES = adns.h tvarith.h w32extra.c
CLEANFILES = adns.h tvarith.h w32extra.c

sources_from_src = adns.h tvarith.h w32extra.c

commonsrc = client.h
if HAVE_W32_SYSTEM
commonsrc += w32extra.c
endif

adnslogres_SOURCES = adnslogres.c $(commonsrc)

adnsheloex_SOURCES = adnsheloex.c $(commonsrc)

adnshost_SOURCES = adh-main.c adh-opts.c adh-query.c adnshost.h $(commonsrc)

adnsresfilter_SOURCES = adnsresfilter.c $(commonsrc)

fanftest_SOURCES = fanftest.c $(commonsrc)

adnstest_SOURCES = adnstest.c $(commonsrc)


./adns.h : $(top_srcdir)/src/adns.h
	cp $< $@

./tvarith.h : $(top_srcdir)/src/tvarith.h
	cp $< $@

./w32extra.c : $(top_srcdir)/src/w32extra.c
	cp $< $@


# Make sure that the library is build before we use it.  This is
# important for make -j.  Because some tools are based on certain
# header files we also directly depend on them too.
$(PROGRAMS): ../src/libadns.la $(sources_from_src)

