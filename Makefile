# adnsMakefile - top-level Makefile
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

SUBDIRS= src dynamic client regress

all:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d all; done

check:	all
	$(MAKE) -C regress check

install:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d install; done

clean:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d clean; done

distclean:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d distclean; done

maintainer-clean:
	set -e; for d in $(SUBDIRS); do $(MAKE) -C $$d maintainer-clean; done