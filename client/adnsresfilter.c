/*
 * adnsresfilter.c
 * - filter which does resolving, not part of the library
 */
/*
 *  This file is
 *    Copyright (C) 1999 Ian Jackson <ian@davenant.greenend.org.uk>
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <search.h>
#include <assert.h>
#include <ctype.h>

#include "adns.h"
#include "config.h"

static void sysfail(const char *what) NONRETURNING;
static void sysfail(const char *what) {
  fprintf(stderr,"adnsresfilter: system call failed: %s: %s\n",what,strerror(errno));
  exit(2);
}

static void outputerr(void) NONRETURNING;
static void outputerr(void) { sysfail("write to stdout"); }

static void usage(void) {
  if (printf("usage: adnsresfilter [<options ...>]\n"
	     "       adnsresfilter  -h|--help\n"
	     "options: -b|--brackets\n"
	     "         -w|--wait\n"
	     "         -u|--unchecked\n")
      == EOF) outputerr();
}

static void usageerr(const char *why) NONRETURNING;
static void usageerr(const char *why) {
  fprintf(stderr,"adnsresfilter: bad usage: %s\n",why);
  usage();
  exit(1);
}

static void adnsfail(const char *what, int e) NONRETURNING;
static void adnsfail(const char *what, int e) {
  fprintf(stderr,"adnsresfilter: adns call failed: %s: %s\n",what,strerror(e));
  exit(2);
}

static int bracket, forever;
static adns_rrtype rrt= adns_r_ptr;

static struct sockaddr_in sa;
static adns_state ads;

static char buf[14];
static int c, cbyte, inbyte, inbuf;
static unsigned char bytes[4];

struct treething {
  unsigned char bytes[4];
  adns_query qu;
  adns_answer *ans;
};

static struct treething *newthing;
static void *treeroot;

static int comparer(const void *a, const void *b) {
  return memcmp(a,b,4);
}

static void restartbuf(void) {
  if (inbuf>0) {
    buf[inbuf++]= 0;
    if (fputs(buf,stdout) < 0) outputerr();
  }
  inbuf= 0;
}

static void procaddr(void) {
  struct treething *foundthing;
  void *expectreturn, **searchfound;
  int r;
  
  if (!newthing) {
    newthing= malloc(sizeof(struct treething));
    if (!newthing) sysfail("malloc");
    newthing->qu= 0;
    newthing->ans= 0;
  }

  memcpy(newthing->bytes,bytes,4);
  searchfound= tsearch(newthing,&treeroot,comparer);
  if (!searchfound) sysfail("tsearch");
  foundthing= *searchfound;

  if (foundthing == newthing) {
    newthing= 0;
    memcpy(&sa.sin_addr,bytes,4);
    r= adns_submit_reverse(ads, (const struct sockaddr*)&sa,
			   rrt,0,foundthing,&foundthing->qu);
    if (r) adnsfail("submit",r);
  }
  if (!foundthing->ans) {
    expectreturn= foundthing;
    r= (forever ? adns_wait : adns_check)
      (ads,&foundthing->qu,&foundthing->ans,&expectreturn);
    assert(r==EAGAIN || (!r && foundthing->ans && expectreturn==foundthing));
  }
  if (foundthing->ans && foundthing->ans->nrrs > 0) {
    if (fputs(foundthing->ans->rrs.str[0],stdout) < 0) outputerr();
    inbuf= 0;
  } else {
    restartbuf();
  }
  cbyte= -1;
}

static void startaddr(void) {
  bytes[cbyte=0]= 0;
  inbyte= 0;
}

static void mustputchar(int c) {
  if (putchar(c) == EOF) outputerr();
}

int main(int argc, const char *const *argv) {
  const char *arg;
  int nbyte, r;

  while ((arg= *++argv)) {
    if (arg[0] != '-') usageerr("no non-option arguments are allowed");
    if (arg[1] == '-') {
      if (!strcmp(arg,"--brackets")) {
	bracket= 1;
      } else if (!strcmp(arg,"--unchecked")) {
	rrt= adns_r_ptr_raw;
      } else if (!strcmp(arg,"--wait")) {
	forever= 1;
      } else if (!strcmp(arg,"--help")) {
	usage(); exit(0);
      } else {
	usageerr("unknown long option");
      }
    } else {
      while ((c= *++arg)) {
	switch (c) {
	case 'b':
	  bracket= 1;
	  break;
	case 'u':
	  rrt= adns_r_ptr_raw;
	  break;
	case 'w':
	  forever= 1;
	  break;
	case 'h':
	  usage(); exit(0);
	default:
	  usageerr("unknown short option");
	}
      }
    }
  }
  if (setvbuf(stdout,0,_IOLBF,0)) sysfail("setvbuf stdout");

  memset(&sa,0,sizeof(sa));
  sa.sin_family= AF_INET;

  r= adns_init(&ads,0,0);  if (r) adnsfail("init",r);

  cbyte= -1;
  inbyte= -1;
  inbuf= 0;
  if (!bracket) startaddr();
  while ((c= getchar()) != EOF) {
    if (cbyte==-1 && bracket && c=='[') {
      buf[inbuf++]= c;
      startaddr();
    } else if (cbyte==-1 && !bracket && !isalnum(c)) {
      mustputchar(c);
      startaddr();
    } else if (cbyte>=0 && inbyte<3 && c>='0' && c<='9' &&
	       (nbyte= bytes[cbyte]*10 + (c-'0')) <= 255) {
      bytes[cbyte]= nbyte;
      buf[inbuf++]= c;
      inbyte++;
    } else if (cbyte>=0 && cbyte<3 && inbyte>0 && c=='.') {
      bytes[++cbyte]= 0;
      buf[inbuf++]= c;
      inbyte= 0;
    } else if (cbyte==3 && inbyte>0 && bracket && c==']') {
      buf[inbuf++]= c;
      procaddr();
    } else if (cbyte==3 && inbyte>0 && !bracket && !isalnum(c)) {
      procaddr();
      mustputchar(c);
      startaddr();
    } else {
      restartbuf();
      mustputchar(c);
      cbyte= -1;
      if (!bracket && !isalnum(c)) startaddr();
    }
  }
  if (ferror(stdin) || fclose(stdin)) sysfail("read stdin");
  if (cbyte==3 && inbyte>0 && !bracket) procaddr();
  if (fclose(stdout)) sysfail("close stdout");
  exit(0);
}
