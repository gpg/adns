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

CC=gcc $(WARNS) $(WERROR) $(OPTIMISE) $(DEBUG) $(XCFLAGS)
DEBUG=-g
OPTIMISE=-O2
WARNS=	-Wall -Wmissing-prototypes -Wwrite-strings -Wstrict-prototypes \
	-Wcast-qual -Wpointer-arith
WERROR=-Werror

HCPPFLAGS:= $(foreach F,			\
	gettimeofday select			\
	socket fcntl connect close		\
	sendto recvfrom read write writev	\
, -D$F=H$F)

LIBOBJS=	types.o event.o query.o reply.o general.o setup.o transmit.o parse.o
HARNLOBJS=	$(addsuffix _d.o, $(basename $(LIBOBJS)))
ALLOBJS=	$(LIBOBJS) $(HARNLOBJS) dtest.o hrecord.o hplayback.o hcommon.o
AUTOCSRCS=	harness.h hrecord.c hcommon.c

TARGETS=	dtest hplayback hrecord

all:		$(TARGETS)

hrecord:	dtest.o hrecord.o hcommon.o $(HARNLOBJS)
hplayback:	dtest.o hplayback.o hcommon.o $(HARNLOBJS)

dtest:		dtest.o $(LIBOBJS)

%_d.o:		%.c
		$(CC) $(HCPPFLAGS) -c -g -o $@ $<

%::	%.m4 hmacros.i4 hsyscalls.i4
	m4 -P $< >$@-a.new
	sed -e 's/hm_comma/,/g; s/hm_squote/'\''/g; /^[	 ]*$$/d' <$@-a.new >$@-b.new
	@mv -f $@-b.new $@; rm -f $@-a.new

.PRECIOUS:	$(AUTOCSRCS)

clean:
		rm -f *.o 

realclean:	clean
		rm -f $(TARGETS) *~ ./#*# core *.orig *.rej

hrecord.o hcommon.o:	adns.h internal.h harness.h
$(HARNLOBJS):		adns.h internal.h
$(LIBOBJS):		adns.h internal.h
dtest.o:		adns.h
