/*
 * transmit.c
 * - construct queries
 * - send queries
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

#include <errno.h>
#include <string.h>

#include <sys/uio.h>

#include "internal.h"

adns_status adns__mkquery(adns_state ads, vbuf *vb, int *id_r,
			  const char *owner, int ol,
			  const typeinfo *typei, adns_queryflags flags) {
  int ll, c, nlabs, id;
  byte label[255], *rqp;
  const char *p, *pe;

#define MKQUERY_ADDB(b) *rqp++= (b)
#define MKQUERY_ADDW(w) (MKQUERY_ADDB(((w)>>8)&0x0ff), MKQUERY_ADDB((w)&0x0ff))

  vb->used= 0;
  if (!adns__vbuf_ensure(vb,DNS_HDRSIZE+strlen(owner)+1+5))
    return adns_s_nolocalmem;
  rqp= vb->buf;

  *id_r= id= (ads->nextid++) & 0x0ffff;

  MKQUERY_ADDW(id);
  MKQUERY_ADDB(0x01); /* QR=Q(0), OPCODE=QUERY(0000), !AA, !TC, RD */
  MKQUERY_ADDB(0x00); /* !RA, Z=000, RCODE=NOERROR(0000) */
  MKQUERY_ADDW(1); /* QDCOUNT=1 */
  MKQUERY_ADDW(0); /* ANCOUNT=0 */
  MKQUERY_ADDW(0); /* NSCOUNT=0 */
  MKQUERY_ADDW(0); /* ARCOUNT=0 */
  p= owner; pe= owner+ol;
  nlabs= 0;
  if (!*p) return adns_s_invalidquerydomain;
  do {
    ll= 0;
    while (p!=pe && (c= *p++)!='.') {
      if (c=='\\') {
	if (!(flags & adns_qf_anyquote)) return adns_s_invalidquerydomain;
	if (ctype_digit(p[0])) {
	  if (ctype_digit(p[1]) && ctype_digit(p[2])) {
	    c= (*p++ - '0')*100 + (*p++ - '0')*10 + (*p++ - '0');
	    if (c >= 256) return adns_s_invalidquerydomain;
	  } else {
	    return adns_s_invalidquerydomain;
	  }
	} else if (!(c= *p++)) {
	  return adns_s_invalidquerydomain;
	}
      }
      if (!(flags & adns_qf_anyquote)) {
	if (c == '-') {
	  if (!ll) return adns_s_invalidquerydomain;
	} else if (!ctype_alpha(c) && !ctype_digit(c)) {
	  return adns_s_invalidquerydomain;
	}
      }
      if (ll == sizeof(label)) return adns_s_invalidquerydomain;
      label[ll++]= c;
    }
    if (!ll) return adns_s_invalidquerydomain;
    if (nlabs++ > 63) return adns_s_domaintoolong;
    MKQUERY_ADDB(ll);
    memcpy(rqp,label,ll); rqp+= ll;
  } while (p!=pe);

  MKQUERY_ADDB(0);
  MKQUERY_ADDW(typei->type & adns__rrt_typemask); /* QTYPE */
  MKQUERY_ADDW(DNS_CLASS_IN); /* QCLASS=IN */

  vb->used= rqp - vb->buf;
  assert(vb->used <= vb->avail);
  
  return adns_s_ok;
}

void adns__query_tcp(adns_query qu, struct timeval now) {
  byte length[2];
  struct iovec iov[2];
  int wr, r;
  adns_state ads;

  if (qu->ads->tcpstate != server_ok) return;

  length[0]= (qu->query_dglen&0x0ff00U) >>8;
  length[1]= (qu->query_dglen&0x0ff);

  ads= qu->ads;
  if (!adns__vbuf_ensure(&ads->tcpsend,ads->tcpsend.used+qu->query_dglen+2)) return;

  timevaladd(&now,TCPMS);
  qu->timeout= now;
  qu->state= query_tcpsent;
  LIST_LINK_TAIL(ads->timew,qu);

  if (ads->tcpsend.used) {
    wr= 0;
  } else {
    iov[0].iov_base= length;
    iov[0].iov_len= 2;
    iov[1].iov_base= qu->query_dgram;
    iov[1].iov_len= qu->query_dglen;
    wr= writev(qu->ads->tcpsocket,iov,2);
    if (wr < 0) {
      if (!(errno == EAGAIN || errno == EINTR || errno == ENOSPC ||
	    errno == ENOBUFS || errno == ENOMEM)) {
	adns__tcp_broken(ads,"write",strerror(errno));
	return;
      }
      wr= 0;
    }
  }

  if (wr<2) {
    r= adns__vbuf_append(&ads->tcpsend,length,2-wr); assert(r);
    wr= 0;
  } else {
    wr-= 2;
  }
  if (wr<qu->query_dglen) {
    r= adns__vbuf_append(&ads->tcpsend,qu->query_dgram+wr,qu->query_dglen-wr); assert(r);
  }
}

static void query_usetcp(adns_query qu, struct timeval now) {
  timevaladd(&now,TCPMS);
  qu->timeout= now;
  qu->state= query_tcpwait;
  LIST_LINK_TAIL(qu->ads->timew,qu);
  adns__query_tcp(qu,now);
  adns__tcp_tryconnect(qu->ads,now);
}

void adns__query_udp(adns_query qu, struct timeval now) {
  struct sockaddr_in servaddr;
  int serv, r;
  adns_state ads;

  assert(qu->state == query_udp);
  if ((qu->flags & adns_qf_usevc) || (qu->query_dglen > DNS_MAXUDP)) {
    query_usetcp(qu,now);
    return;
  }

  if (qu->udpretries >= UDPMAXRETRIES) {
    adns__query_fail(qu,adns_s_timeout);
    return;
  }

  serv= qu->udpnextserver;
  memset(&servaddr,0,sizeof(servaddr));

  ads= qu->ads;
  servaddr.sin_family= AF_INET;
  servaddr.sin_addr= ads->servers[serv].addr;
  servaddr.sin_port= htons(DNS_PORT);
  
  r= sendto(ads->udpsocket,qu->query_dgram,qu->query_dglen,0,&servaddr,sizeof(servaddr));
  if (r<0 && errno == EMSGSIZE) { query_usetcp(qu,now); return; }
  if (r<0) adns__warn(ads,serv,0,"sendto failed: %s",strerror(errno));
  
  timevaladd(&now,UDPRETRYMS);
  qu->timeout= now;
  qu->udpsent |= (1<<serv);
  qu->udpnextserver= (serv+1)%ads->nservers;
  qu->udpretries++;
  LIST_LINK_TAIL(ads->timew,qu);
}
