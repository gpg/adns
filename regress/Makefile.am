# regress/Makefile.am - regression test Makefile
# Copyright (C) 2008 g10 Code GmbH
# 
#  This file is part of adns, which is
#    Copyright (C) 1997-2000,2003,2006  Ian Jackson
#    Copyright (C) 1999-2000,2003,2006  Tony Finch
#    Copyright (C) 1991 Massachusetts Institute of Technology
#  (See the file INSTALL for full details.)
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2, or (at your option)
#  any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

adnssrcdir = $(top_srcdir)/src
adnsclientdir = $(top_srcdir)/client

clients  = adnstest_record adnstest_playback
clients += adnslogres_record adnslogres_playback
clients += adnsheloex_record adnsheloex_playback
clients += adnshost_record adnshost_playback
clients += fanftest_record fanftest_playback
if HAVE_TSEARCH
clients += adnsresfilter_record adnsresfilter_playback
endif

# Define adnssources (using $(adnssrcdir) does not work.)  We need to
# build a static version of the library here so that we are able to
# redirect all system calls.  On a ELF system it would be easier to
# use an LD_PRELOAD mechanism instead but that is not portable.  Using
# sources from another directory is a bit problematic because the
# automatic depency tracky may get messed up if we have a name clash.
# Fixme: A better solution would be to build a harnessed version of
# the library in src and link the test programs with that harnessed
# library.
include $(top_srcdir)/src/source.list

# Define casefiles and initfiles.
include $(srcdir)/casefiles.list
include $(srcdir)/initfiles.list

noinst_PROGRAMS = $(clients)

harnesssrcs = hrecord.c.m4 hplayback.c.m4 hcommon.c.m4 \
              harness.h.m4 hsyscalls.h.m4 hredirect.h.m4

BUILT_SOURCES = hrecord.c hplayback.c hcommon.c \
                harness.h hsyscalls.h hredirect.h

DISTCLEANFILES = harness.h hsyscalls.h hredirect.h \
                 output-*.{err,out,leftover,report}

EXTRA_DIST = hmacros.i4 hsyscalls.i4 $(harnesssrcs) \
	     checkall r1test \
             adnshost-xinitflags.text \
             adnslogres-xinitflags.text \
	     adnsresfilter-xinitflags.text \
	     $(initfiles) $(casefiles)

TESTS = checkall

SUFFIXES = .c.m4 .h.m4

AM_CPPFLAGS = $(PLATFORMCPPFLAGS) -DADNS_REGRESS_TEST -I. -I$(adnssrcdir)

LDADD = 

recordsrc = hrecord.c hcommon.c $(adnssources)
playbacksrc = hplayback.c hcommon.c $(adnssources)

adnstest_record_SOURCES   = $(adnsclientdir)/adnstest.c $(recordsrc)
adnstest_playback_SOURCES = $(adnsclientdir)/adnstest.c $(playbacksrc)

adnslogres_record_SOURCES = $(adnsclientdir)/adnslogres.c $(recordsrc)
adnslogres_playback_SOURCES = $(adnsclientdir)/adnslogres.c $(playbacksrc)

adnsheloex_record_SOURCES = $(adnsclientdir)/adnsheloex.c $(recordsrc)
adnsheloex_playback_SOURCES = $(adnsclientdir)/adnsheloex.c $(playbacksrc)


adnshost_commonsrc = \
	$(adnsclientdir)/adh-main.c \
	$(adnsclientdir)/adh-opts.c \
	$(adnsclientdir)/adh-query.c \
	$(adnsclientdir)/adnshost.h
adnshost_record_SOURCES = $(adnshost_commonsrc) $(recordsrc)
adnshost_playback_SOURCES = $(adnshost_commonsrc) $(playbacksrc)

fanftest_record_SOURCES = $(adnsclientdir)/fanftest.c $(recordsrc)
fanftest_playback_SOURCES = $(adnsclientdir)/fanftest.c $(playbacksrc)

adnsresfilter_record_SOURCES = $(adnsclientdir)/adnsresfilter.c $(recordsrc)
adnsresfilter_playback_SOURCES = $(adnsclientdir)/adnsresfilter.c $(playbacksrc)


$(harnesssrcs):	hmacros.i4 hsyscalls.i4

.c.m4.c: 
include $(srcdir)/m4-to-c.rule

.h.m4.h: 
include $(srcdir)/m4-to-c.rule


