# regress/Makefile - regression test Makefile
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

DIRCFLAGS=	-I../src

HCPPFLAGS:= $(foreach F,			\
	gettimeofday select			\
	socket fcntl connect close		\
	sendto recvfrom read write writev	\
, -D$F=H$F)

HARNLOBJS=	$(addsuffix _d.o, $(basename $(LIBOBJS)))
ALLOBJS=	$(HARNLOBJS) dtest.o hrecord.o hplayback.o hcommon.o
AUTOCSRCS=	harness.h hrecord.c hplayback.c hcommon.c

TARGETS=	hplayback hrecord

include ../settings.make
include ../src/adns.make

.PRECIOUS:	$(AUTOCSRCS)

check:		$(TARGETS)
		./checkall

hrecord:	../client/adnstest.o hrecord.o hcommon.o $(HARNLOBJS)
hplayback:	../client/adnstest.o hplayback.o hcommon.o $(HARNLOBJS)

%_d.o:		../src/%.c
		$(CC) $(HCPPFLAGS) -c -g -o $@ $<

$(ALLOBJS):	../src/adns.h ../src/internal.h harness.h

%::	%.m4 hmacros.i4 hsyscalls.i4
	m4 -P $< >$@-a.new
	sed -e 's/hm_comma/,/g; s/hm_squote/'\''/g; /^[	 ]*$$/d' <$@-a.new >$@-b.new
	@mv -f $@-b.new $@; rm -f $@-a.new
