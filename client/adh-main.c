/*
 * adh-main.c
 * - useful general-purpose resolver client program
 *   main program and useful subroutines
 */
/*
 *  This file is
 *    Copyright (C) 1997-1999 Ian Jackson <ian@davenant.greenend.org.uk>
 *
 *  It is part of adns, which is
 *    Copyright (C) 1997-1999 Ian Jackson <ian@davenant.greenend.org.uk>
 *    Copyright (C) 1999 Tony Finch <dot@dotat.at>
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

void sysfail(const char *what, int errnoval) {
  fprintf(stderr,"adnshost failed: %s: %s\n",what,strerror(errnoval));
  exit(10);
}

static void domain_do_arg(const char *domain) {
  if (ov_pipe) usageerr("-f/--pipe not consistent with domains on command line");
  domain_do(arg);
}

static void of_type(const struct optinfo *oi, const char *arg) { abort(); }

int main(int argc, const char *const *argv) {
  const char *arg;
  const 
  
  while (arg= *++argv) {
    if (arg[0] != '-') {
      if (arg[1] == '-') {
	oip= opt_findl(arg+2);
	if (oip->type == ot_funcarg) {
	  arg= *++argv;
	  if (!arg) usageerr("option --%s requires a value argument",oip->lopt);
	} else {
	  arg= 0;
	}
	opt_do(oip,arg);
      } else if (arg[1] == 0) {
	arg= *++argv;
	if (!arg) usageerr("option `-' must be followed by a domain");
	domain_do_arg(arg);
      } else { /* arg[1] != '-', != '\0' */
	++arg;
	while (*arg) {
	  oip= opt_finds(&arg);
	  if (oip->type == ot_funcarg) {
	    if (!*arg) {
	      arg= *++argv;
	      if (!arg) usageerr("option -%s requires a value argument",oip->sopt);
	    }
	    arg= "";
	  } else {
	    arg= 0;
	  }
	  opt_do(oip,arg);
	}
      }
    } else { /* arg[0] != '-' */
      domain_do_arg(arg);
    }
  }

  if (ov_pipe) {
    
      if (ov_pipe) usageerr("-f/--pipe not 
	  
	if (oip && ads) usageerr("global option %s must precede all query domains",arg);
	if (!oip) oip= opt_findl(arg+2,perquery_options);
	if (!oip) usageerr("unknown option %s",arg);
	}

	if (!oip && 
	if (!oip) {
  }
  while (argv[1] && argv[1][0] == '-') {
    if (argv[1][1] == '-') {
      oip= findlong(
  }
  of_help(0,0);
  abort();
}
