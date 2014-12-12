# Makefile.am - Top level makefile for adns
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

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = autogen.sh changelog.Debian \
             README.html GPL-vs-LGPL LICENCE.WAIVERS


if CROSS_COMPILING
regress =
else
regress = regress
endif


SUBDIRS = m4 src client ${regress}

# Fixme we need to test that lynx is available.
README:	README.html
	lynx -dump -number_links -cfg=/dev/null ./README.html >README.tmp
	mv -f README.tmp README


dist-hook:
	@set -e; echo "$(VERSION)" > $(distdir)/VERSION

stowinstall:
	$(MAKE) $(AM_MAKEFLAGS) install prefix=/usr/local/stow/adns

