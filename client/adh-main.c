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

#include "adnshost.h"

void sysfail(const char *what, int errnoval) {
  fprintf(stderr,"adnshost failed: %s: %s\n",what,strerror(errnoval));
  exit(10);
}

void usageerr(const char *fmt, ...) {
  va_list al;
  fputs("adnshost usage error: ",stderr);
  va_start(al,fmt);
  vfprintf(stderr,fmt,al);
  va_end(al);
  putc('\n',stderr);
  exit(11);
}

void outerr(void) {
  sysfail("write to stdout",errno);
}

static void domain_do_arg(const char *domain) {
  if (ov_pipe) usageerr("-f/--pipe not consistent with domains on command line");
  ensure_adns_init();
  query_do(domain);
}

void *xmalloc(size_t sz) {
  void *p;

  p= malloc(sz); if (!p) sysfail("malloc",sz);
  return p;
}

char *xstrsave(const char *str) {
  char *p;
  
  p= xmalloc(strlen(str)+1);
  strcpy(p,str);
  return p;
}

void of_type(const struct optioninfo *oi, const char *arg) { abort(); }

int rcode;

void setnonblock(int fd, int nonblock) { }

static void read_query(void) { abort(); }

int main(int argc, const char *const *argv) {
  const char *arg;
  const struct optioninfo *oip;
  struct timeval *tv, tvbuf;
  adns_query qu;
  void *qun_v;
  adns_answer *answer;
  int r, maxfd, invert;
  fd_set readfds, writefds, exceptfds;
  
  while ((arg= *++argv)) {
    if (arg[0] == '-' || arg[0] == '+') {
      if (arg[0] == '-' && arg[1] == '-') {
	if (!strncmp(arg,"--no-",5)) {
	  invert= 1;
	  oip= opt_findl(arg+5);
	} else {
	  invert= 0;
	  oip= opt_findl(arg+2);
	}
	if (oip->type == ot_funcarg) {
	  arg= *++argv;
	  if (!arg) usageerr("option --%s requires a value argument",oip->lopt);
	} else {
	  arg= 0;
	}
	opt_do(oip,arg,invert);
      } else if (arg[0] == '-' && arg[1] == 0) {
	arg= *++argv;
	if (!arg) usageerr("option `-' must be followed by a domain");
	domain_do_arg(arg);
      } else { /* arg[1] != '-', != '\0' */
	invert= (arg[0] == '+');
	++arg;
	while (*arg) {
	  oip= opt_finds(&arg);
	  if (oip->type == ot_funcarg) {
	    if (!*arg) {
	      arg= *++argv;
	      if (!arg) usageerr("option -%s requires a value argument",oip->sopt);
	    }
	    opt_do(oip,arg,invert);
	    arg= "";
	  } else {
	    opt_do(oip,0,invert);
	  }
	}
      }
    } else { /* arg[0] != '-' */
      domain_do_arg(arg);
    }
  }

  if (!ov_pipe && !ads) usageerr("no domains given, and -f/--pipe not used; try --help");

  for (;;) {
    for (;;) {
      qu= ov_asynch ? 0 : outstanding.head ? outstanding.head->qu : 0;
      r= adns_check(ads,&qu,&answer,&qun_v);
      if (r == EAGAIN) break;
      if (r == ESRCH) { if (!ov_pipe) goto x_quit; else break; }
      assert(!r);
      query_done(qun_v,answer);
    }
    maxfd= 0;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    if (ov_pipe) {
      maxfd= 1;
      FD_SET(0,&readfds);
    }
    tv= 0;
    adns_beforeselect(ads, &maxfd, &readfds,&writefds,&exceptfds, &tv,&tvbuf,0);
    r= select(maxfd, &readfds,&writefds,&exceptfds, tv);
    if (r == -1) {
      if (errno == EINTR) continue;
      sysfail("select",errno);
    }
    adns_afterselect(ads, maxfd, &readfds,&writefds,&exceptfds, 0);
    if (ov_pipe && FD_ISSET(0,&readfds)) read_query();
  }
x_quit:
  if (fclose(stdout)) outerr();
  exit(rcode);
}
