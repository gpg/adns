# dynamic/Makefile - dynamic library Makefile
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

TARGETS=	$(LIBFILE)

include ../settings.make
include ../src/adns.make

ALLOBJS=	$(addsuffix _p.o, $(basename $(LIBOBJS)))

install:
		$(INSTALL_LIB) $(LIBFILE) $(lib_dir)
		$(INSTALL_HDR) ../src/adns.h $(include_dir)

$(LIBFILE):	$(ALLOBJS)
		rm -f $@
		$(CC) -shared -Wxl,soname=libadns.so.$(MAJOR) -o $@ $(ALLOBJS) -lc

%_p.o:		../src/%.c ../src/adns.h ../src/internal.h
		$(CC) -fpic -I../src -c -o $@ $<

$(LIBOBJS):	
