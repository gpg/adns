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
	    adns__diag_domain(qu->ads,-1,0, &vb,
			      qu->query_dgram,qu->query_dglen,DNS_HDRSIZE),
	    qu->typei ? qu->typei->rrtname : "<unknown>");
    if (qu->typei && qu->typei->fmtname)
      fprintf(stderr,"(%s)",qu->typei->fmtname);
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

int adns__vbuf_appendstr(vbuf *vb, const char *data) {
  int l;
  l= strlen(data);
  return adns__vbuf_append(vb,data,l);
}

void adns__vbuf_free(vbuf *vb) {
  free(vb->buf);
  adns__vbuf_init(vb);
}

/* Additional diagnostic functions */

const char *adns__diag_domain(adns_state ads, int serv, adns_query qu,
			      vbuf *vb, const byte *dgram, int dglen, int cbyte) {
  adns_status st;

  st= adns__parse_domain(ads,serv,qu,vb, pdf_quoteok, dgram,dglen,&cbyte,dglen);
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

adns_status adns_rr_info(adns_rrtype type,
			 const char **rrtname_r, const char **fmtname_r,
			 int *len_r,
			 const void *datap, char **data_r) {
  const typeinfo *typei;
  vbuf vb;
  adns_status st;

  typei= adns__findtype(type);
  if (!typei) return adns_s_notimplemented;

  if (rrtname_r) *rrtname_r= typei->rrtname;
  if (fmtname_r) *fmtname_r= typei->fmtname;
  if (len_r) *len_r= typei->rrsz;

  if (!datap) return adns_s_ok;
  
  adns__vbuf_init(&vb);
  st= typei->convstring(&vb,datap);
  if (st) goto x_freevb;
  if (!adns__vbuf_append(&vb,"",1)) { st= adns_s_nolocalmem; goto x_freevb; }
  assert(strlen(vb.buf) == vb.used-1);
  *data_r= realloc(vb.buf,vb.used);
  if (!*data_r) *data_r= vb.buf;
  return adns_s_ok;

 x_freevb:
  adns__vbuf_free(&vb);
  return st;
}

#define SINFO(n,s) { adns_s_##n, s }

static const struct sinfo {
  adns_status st;
  const char *string;
} sinfos[]= {
  SINFO(  ok,                  "OK"                                    ),
  SINFO(  timeout,             "Timed out"                             ),
  SINFO(  nolocalmem,          "Out of memory"                         ),
  SINFO(  allservfail,         "No working nameservers"                ),
  SINFO(  servfail,            "Nameserver failure"                    ),
  SINFO(  notimplemented,      "Query not implemented"                 ),
  SINFO(  refused,             "Refused by nameserver"                 ),
  SINFO(  reasonunknown,       "Reason unknown"                        ),
  SINFO(  norecurse,           "Recursion denied by nameserver"        ),
  SINFO(  serverfaulty,        "Nameserver sent bad data"              ),
  SINFO(  unknownreply,        "Reply from nameserver not understood"  ),
  SINFO(  invaliddata,         "Invalid data"                          ),
  SINFO(  inconsistent,        "Inconsistent data"                     ),
  SINFO(  cname,               "RR refers to an alias"                 ),
  SINFO(  invalidanswerdomain, "Received syntactically invalid domain" ),
  SINFO(  nxdomain,            "No such domain"                        ),
  SINFO(  nodata,              "No such data"                          ),
  SINFO(  invalidquerydomain,  "Domain syntactically invalid"          ),
  SINFO(  domaintoolong,       "Domain name too long"                  )
};

static int si_compar(const void *key, const void *elem) {
  const adns_status *st= key;
  const struct sinfo *si= elem;

  return *st < si->st ? -1 : *st > si->st ? 1 : 0;
}

const char *adns_strerror(adns_status st) {
  static char buf[100];

  const struct sinfo *si;

  si= bsearch(&st,sinfos,sizeof(sinfos)/sizeof(*si),sizeof(*si),si_compar);
  if (si) return si->string;
  
  snprintf(buf,sizeof(buf),"code %d",st);
  return buf;
}
