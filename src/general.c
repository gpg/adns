/*
 * general.c
 * - diagnostic functions
 * - vbuf handling
 */
/*
 *  This file is part of adns, which is Copyright (C) 1997, 1998 Ian Jackson
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

#include <stdlib.h>

#include <arpa/inet.h>

#include "internal.h"

/* Core diagnostic functions */

void adns__vdiag(adns_state ads, const char *pfx, adns_initflags prevent,
		 int serv, adns_query qu, const char *fmt, va_list al) {
  const char *bef, *aft;
  vbuf vb;
  if (!(ads->iflags & adns_if_debug) && (!prevent || (ads->iflags & prevent))) return;

  fprintf(stderr,"adns%s: ",pfx);

  vfprintf(stderr,fmt,al);

  bef= " (";
  aft= "\n";

  if (qu && qu->query_dgram) {
    adns__vbuf_init(&vb);
    fprintf(stderr,"%sQNAME=%s, QTYPE=%s",
	    bef,
	    adns__diag_domain(qu->ads,-1,0, &vb,qu->flags,
			      qu->query_dgram,qu->query_dglen,DNS_HDRSIZE),
	    qu->typei ? qu->typei->name : "<unknown>");
    bef=", "; aft=")\n";
  }
  
  if (serv>=0) {
    fprintf(stderr,"%sNS=%s",bef,inet_ntoa(ads->servers[serv].addr));
    bef=", "; aft=")\n";
  }

  fputs(aft,stderr);
}

void adns__debug(adns_state ads, int serv, adns_query qu, const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  adns__vdiag(ads," debug",0,serv,qu,fmt,al);
  va_end(al);
}

void adns__warn(adns_state ads, int serv, adns_query qu, const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  adns__vdiag(ads," warning",adns_if_noerrprint|adns_if_noserverwarn,serv,qu,fmt,al);
  va_end(al);
}

void adns__diag(adns_state ads, int serv, adns_query qu, const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  adns__vdiag(ads,"",adns_if_noerrprint,serv,qu,fmt,al);
  va_end(al);
}

/* vbuf functions */

void adns__vbuf_init(vbuf *vb) {
  vb->used= vb->avail= 0; vb->buf= 0;
}

int adns__vbuf_ensure(vbuf *vb, int want) {
  void *nb;
  
  if (vb->avail >= want) return 1;
  nb= realloc(vb->buf,want); if (!nb) return 0;
  vb->buf= nb;
  vb->avail= want;
  return 1;
}
  
void adns__vbuf_appendq(vbuf *vb, const byte *data, int len) {
  memcpy(vb->buf+vb->used,data,len);
  vb->used+= len;
}

int adns__vbuf_append(vbuf *vb, const byte *data, int len) {
  int newlen;
  void *nb;

  newlen= vb->used+len;
  if (vb->avail < newlen) {
    if (newlen<20) newlen= 20;
    newlen <<= 1;
    nb= realloc(vb->buf,newlen);
    if (!nb) { newlen= vb->used+len; nb= realloc(vb->buf,newlen); }
    if (!nb) return 0;
    vb->buf= nb;
    vb->avail= newlen;
  }
  adns__vbuf_appendq(vb,data,len);
  return 1;
}

void adns__vbuf_free(vbuf *vb) {
  free(vb->buf);
  adns__vbuf_init(vb);
}

/* Additional diagnostic functions */

const char *adns__diag_domain(adns_state ads, int serv, adns_query qu, vbuf *vb,
			      int flags, const byte *dgram, int dglen, int cbyte) {
  adns_status st;

  st= adns__parse_domain(ads,serv,qu,vb, flags,dgram,dglen,&cbyte,dglen);
  if (st == adns_s_nolocalmem) {
    return "<cannot report domain... out of memory>";
  }
  if (st) {
    vb->used= 0;
    if (!(adns__vbuf_appendstr(vb,"<bad format... ") &&
	  adns__vbuf_appendstr(vb,adns_strerror(st)) &&
	  adns__vbuf_appendstr(vb,">") &&
	  adns__vbuf_append(vb,"",1))) {
      return "<cannot report bad format... out of memory>";
    }
  }
  if (!vb->used) {
    adns__vbuf_appendstr(vb,"<truncated ...>");
    adns__vbuf_append(vb,"",1);
  }
  return vb->buf;
}
    
const char *adns_strerror(adns_status st) {
  static char buf[100];
  snprintf(buf,sizeof(buf),"code %d",st);
  return buf;
}
