# settings.make - main configuration settings for Makefiles
#  
#  This file is part of adns, which is Copyright (C) 1997, 1998 Ian Jackson
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
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 

MAJOR=		1
MINOR=		0
LIBFILE=	libadns.so.$(MAJOR).$(MINOR)

CC=gcc $(WARNS) $(WERROR) $(OPTIMISE) $(DEBUG) $(XCFLAGS) $(DIRCFLAGS)
DEBUG=-g
OPTIMISE=-O2
WARNS=	-Wall -Wmissing-prototypes -Wwrite-strings -Wstrict-prototypes \
	-Wcast-qual -Wpointer-arith
WERROR=-Werror

prefix=		/usr/local
bin_dir=	$(prefix)/bin
lib_dir=	$(prefix)/lib
include_dir=	$(prefix)/include

INSTALL=	install -o 0 -g 0
INSTALL_LIB=	$(INSTALL) -m 755
INSTALL_BIN=	$(INSTALL) -m 755
INSTALL_HDR=	$(INSTALL) -m 644

all:		$(TARGETS)

clean:
		rm -f *.o 

maintainer-clean distclean:	clean
		rm -f $(TARGETS) *~ ./#*# core *.orig *.rej
