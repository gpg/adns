/**/

#include "internal.h"

adns_status adns__mkquery(adns_state ads, const char *owner, int ol, int id,
			  adns_rrtype type, adns_queryflags flags, int *qml_r) {
  int ll, c, nlabs, qbufreq;
  unsigned char label[255], *nqbuf;
  const char *p, *pe;

#define MKQUERY_ADDB(b) *nqbuf++= (b)
#define MKQUERY_ADDW(w) (MKQUERY_ADDB(((w)>>8)&0x0ff), MKQUERY_ADDB((w)&0x0ff))

  qbufreq= 12+strlen(owner)+3;
  if (ads->qbufavail < qbufreq) {
    nqbuf= realloc(ads->qbuf,qbufreq);
    if (!nqbuf) return adns_s_nolocalmem;
    ads->qbuf= nqbuf; ads->qbufavail= qbufreq;
  }
  nqbuf= ads->qbuf;
  
  MKQUERY_ADDW(id);
  MKQUERY_ADDB(0x01); /* QR=Q(0), OPCODE=QUERY(0000), !AA, !TC, RD */
  MKQUERY_ADDB(0x00); /* !RA, Z=000, RCODE=NOERROR(0000) */
  MKQUERY_ADDW(1); /* QDCOUNT=1 */
  MKQUERY_ADDW(0); /* ANCOUNT=0 */
  MKQUERY_ADDW(0); /* NSCOUNT=0 */
  MKQUERY_ADDW(0); /* ARCOUNT=0 */
  p= owner; pe= owner+ol;
  nlabs= 0;
  if (!*p) return adns_s_invaliddomain;
  do {
    ll= 0;
    while (p!=pe && (c= *p++)!='.') {
      if (c=='\\') {
	if (!(flags & adns_f_anyquote)) return adns_s_invaliddomain;
	if (ctype_digit(p[0])) {
	  if (ctype_digit(p[1]) && ctype_digit(p[2])) {
	    c= (*p++ - '0')*100 + (*p++ - '0')*10 + (*p++ - '0');
	    if (c >= 256) return adns_s_invaliddomain;
	  } else {
	    return adns_s_invaliddomain;
	  }
	} else if (!(c= *p++)) {
	  return adns_s_invaliddomain;
	}
      }
      if (!(flags & adns_f_anyquote)) {
	if (ctype_digit(c) || c == '-') {
	  if (!ll) return adns_s_invaliddomain;
	} else if ((c < 'a' || c > 'z') && (c < 'A' && c > 'Z')) {
	  return adns_s_invaliddomain;
	}
      }
      if (ll == sizeof(label)) return adns_s_invaliddomain;
      label[ll++]= c;
    }
    if (!ll) return adns_s_invaliddomain;
    if (nlabs++ > 63) return adns_s_invaliddomain;
    MKQUERY_ADDB(ll);
    memcpy(nqbuf,label,ll); nqbuf+= ll;
  } while (p!=pe);

  MKQUERY_ADDB(0);
  MKQUERY_ADDW(type & adns__rrt_typemask); /* QTYPE */
  MKQUERY_ADDW(1); /* QCLASS=IN */

  *qml_r= nqbuf - ads->qbuf;
  
  return adns_s_ok;
}

static void quproc_tosend_tcp(adns_state ads, adns_query qu, struct timeval now) {
  unsigned char length[2];
  struct iovec iov[2];

  length[0]= (qu->querylen&0x0ff00U) >>8;
  length[1]= (qu->querylen&0x0ff);
  
  adns__tcp_tryconnect(ads);
  /* fixme: try sending queries as soon as server comes up */
  /* fixme: use vbuf_ensure, and preallocate buffer space */
  if (ads->tcpstate != server_ok) return;

  DLIST_UNLINK(ads->tosend,qu);
  timevaladd(&now,TCPMS);
  qu->timeout= now;
  qu->senttcpserver= ads->tcpserver;
  DLIST_LINKTAIL(ads->timew,qu);

  if (ads->opbufused) {
    r= 0;
  } else {
    iov[0].iovbase= length;
    iov[0].iov_len= 2;
    iov[1].iovbase= qu->querymsg;
    iov[1].iov_len= qu->querylen;
    r= writev(ads->tcpsocket,iov,2);
    if (r < 0) {
      if (!(errno == EAGAIN || errno == EINTR || errno == ENOSPC ||
	    errno == ENOBUFS || errno == ENOMEM)) {
	adns__tcp_broken(ads,"write",strerror(errno));
	return;
      }
      r= 0;
    }
  }
  
  if (r < qu->querylen+2) {
    newopbufused= qu->opbufused + qu->querylen + 2 - r;
    if (newopbufused > ads->opbufavail) {
      newopbufavail= ads->newopbufused<<1;
      newopbuf= realloc(newopbufavail);
      if (!newopbuf) {
	DLIST_UNLINK(ads->timew,qu);
	query_fail(ads,qu,adns_s_nolocalmem);
	return;
      }
      ads->opbuf= newopbuf;
      ads->opbufavail= newopbufavail;
    }
    if (r<2) {
      memcpy(ads->opbuf+ads->opbufused,length+r,2-r);
      ads->opbufused += (2-r);
      r= 0;
    } else {
      r -= 2;
    }
    memcpy(ads->opbuf+ads->opbufused,qu->querymsg+r,qu->querylen-r);
    ads->opbufused= newopbufused;
  }
}

void adns__quproc_tosend(adns_state ads, adns_query qu, struct timeval now) {
  /* Query must be on the `tosend' queue, and we guarantee to remove it.
   */
  struct sockaddr_in servaddr;
  int serv;

  if (qu->nextudpserver == -1) { quproc_tosend_tcp(ads,qu,now); return; }
  if (qu->querylen > UDPMAXDGRAM) {
    qu->nextudpserver= -1;
    quproc_tosend_tcp(ads,qu,now);
    return;
  }
  
  if (qu->udpretries >= UDPMAXRETRIES) {
    DLIST_UNLINK(ads->tosend,qu);
    query_fail(ads,qu,adns_s_notresponding);
    return;
  }

  serv= qu->nextudpserver;
  memset(&servaddr,0,sizeof(servaddr));
  servaddr.sin_family= AF_INET;
  servaddr.sin_addr= ads->servers[serv].addr;
  servaddr.sin_port= htons(NSPORT);
  
  r= sendto(ads->udpsocket,qu->querymsg,qu->querylen,0,&servaddr,sizeof(servaddr));
  if (r<0 && errno == EMSGSIZE) {
    qu->nextudpserver= -1;
    quproc_tosend_tcp(ads,qu,now); return;
  }
  if (r<0) warn("sendto %s failed: %s",inet_ntoa(servaddr.sin_addr),strerror(errno));
  
  DLIST_UNLINK(ads->tosend,qu);
  timevaladd(&now,UDPRETRYMS);
  qu->timeout= now;
  qu->sentudp |= (1<<serv);
  qu->nextudpserver= (serv+1)%ads->nservers;
  qu->udpretries++;
  DLIST_LINKTAIL(ads->timew,qu);
}

void adns__query_fail(adns_state ads, adns_query qu, adns_status stat) {
  adns_answer *ans;
  
  ans= qu->answer;
  if (!ans) ans= malloc(sizeof(*qu->answer));
  if (ans) {
    ans->status= stat;
    ans->cname= 0;
    ans->type= qu->type;
    ans->nrrs= 0;
  }
  qu->answer= ans;
  qu->id= -1;
  LIST_LINK_TAIL(ads->output,qu);
}
