/**/

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <sys/uio.h>

#include "internal.h"

adns_status adns__mkquery(adns_state ads, vbuf *vb,
			  const char *owner, int ol, int *id_r,
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
  if (!*p) return adns_s_invaliddomain;
  do {
    ll= 0;
    while (p!=pe && (c= *p++)!='.') {
      if (c=='\\') {
	if (!(flags & adns_qf_anyquote)) return adns_s_invaliddomain;
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
      if (!(flags & adns_qf_anyquote)) {
	if (ctype_digit(c) || c == '-') {
	  if (!ll) return adns_s_invaliddomain;
	} else if (!ctype_alpha(c)) {
	  return adns_s_invaliddomain;
	}
      }
      if (ll == sizeof(label)) return adns_s_invaliddomain;
      label[ll++]= c;
    }
    if (!ll) return adns_s_invaliddomain;
    if (nlabs++ > 63) return adns_s_invaliddomain;
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

void adns__query_tcp(adns_state ads, adns_query qu, struct timeval now) {
  /* Query must be in state tcpwait/timew; it will be moved to a new state
   * if possible and no further processing can be done on it for now.
   * (Resulting state is one of tcpwait/timew (if server not connected),
   *  tcpsent/timew, child/childw or done/output.)
   *
   * adns__tcp_tryconnect should already have been called - _tcp
   * will only use an existing connection (if there is one), which it
   * may break.  If the conn list lost then the caller is responsible for any
   * reestablishment and retry.
   */
  byte length[2];
  struct iovec iov[2];
  int wr, r;

  if (ads->tcpstate != server_ok) return;

  length[0]= (qu->query_dglen&0x0ff00U) >>8;
  length[1]= (qu->query_dglen&0x0ff);
  
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
    wr= writev(ads->tcpsocket,iov,2);
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

static void query_usetcp(adns_state ads, adns_query qu, struct timeval now) {
  timevaladd(&now,TCPMS);
  qu->timeout= now;
  qu->state= query_tcpwait;
  LIST_LINK_TAIL(ads->timew,qu);
  adns__query_tcp(ads,qu,now);
  adns__tcp_tryconnect(ads,now);
}

void adns__query_udp(adns_state ads, adns_query qu, struct timeval now) {
  /* Query must be in state udp/NONE; it will be moved to a new state,
   * and no further processing can be done on it for now.
   * (Resulting state is one of udp/timew, tcpwait/timew (if server not connected),
   *  tcpsent/timew, child/childw or done/output.)
   */
  struct sockaddr_in servaddr;
  int serv, r;

  assert(qu->state == query_udp);
  if ((qu->flags & adns_qf_usevc) || (qu->query_dglen > DNS_MAXUDP)) {
    query_usetcp(ads,qu,now);
    return;
  }

  if (qu->udpretries >= UDPMAXRETRIES) {
    adns__query_fail(ads,qu,adns_s_timeout);
    return;
  }

  serv= qu->udpnextserver;
  memset(&servaddr,0,sizeof(servaddr));
  servaddr.sin_family= AF_INET;
  servaddr.sin_addr= ads->servers[serv].addr;
  servaddr.sin_port= htons(DNS_PORT);
  
  r= sendto(ads->udpsocket,qu->query_dgram,qu->query_dglen,0,&servaddr,sizeof(servaddr));
  if (r<0 && errno == EMSGSIZE) { query_usetcp(ads,qu,now); return; }
  if (r<0) adns__warn(ads,serv,0,"sendto failed: %s",strerror(errno));
  
  timevaladd(&now,UDPRETRYMS);
  qu->timeout= now;
  qu->udpsent |= (1<<serv);
  qu->udpnextserver= (serv+1)%ads->nservers;
  qu->udpretries++;
  LIST_LINK_TAIL(ads->timew,qu);
}

static void adns__query_done(adns_state ads, adns_query qu) {
  adns_answer *ans;
  allocnode *an, *ann;
  int i;

  qu->answer= ans= realloc(qu->answer,
			   MEM_ROUND(MEM_ROUND(sizeof(*ans)) +
				     qu->interim_allocd));
  qu->final_allocspace= (byte*)qu->answer + MEM_ROUND(sizeof(*ans));

  adns__makefinal_str(qu,&ans->cname);
  if (ans->nrrs) {
    adns__makefinal_block(qu,&ans->rrs.untyped,ans->rrsz*ans->nrrs);
    for (i=0; i<ans->nrrs; i++)
      qu->typei->makefinal(ads,qu,ans->rrs.bytes+ans->rrsz*i);
  }

  for (an= qu->allocations; an; an= ann) { ann= an->next; free(an); }

  adns__vbuf_free(&qu->vb);
  
  qu->id= -1;
  LIST_LINK_TAIL(ads->output,qu);
}

void adns__reset_cnameonly(adns_state ads, adns_query qu) {
  assert(qu->final_allocspace);
  qu->answer->nrrs= 0;
  qu->answer->rrs= 0;
  qu->interim_allocd= qu->answer->cname ? MEM_ROUND(strlen(qu->answer->cname)+1) : 0;
}

void adns__query_fail(adns_state ads, adns_query qu, adns_status stat) {
  adns__reset_cnameonly(ads,qu);
  qu->answer->status= stat;
  adns__query_done(ads,qu);
}
