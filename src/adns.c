/**/

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include <netdb.h>
#include <arpa/nameser.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "adns-internal.h"

#define LIST_UNLINK_PART(list,node,part) \
  do { \
    if ((node)->back) (node)->back->part next= (node)->part next; \
      else                        (list).head= (node)->part next; \
    if ((node)->next) (node)->next->part back= (node)->part back; \
      else                        (list).tail= (node)->part back; \
  } while(0)

#define LIST_LINK_TAIL_PART(list,node,part) \
  do { \
    (node)->part back= 0; \
    (node)->part next= (list).tail; \
    if ((list).tail) (list).tail->part back= (node); else (list).part head= (node); \
    (list).tail= (node); \
  } while(0)

#define LIST_UNLINK(list,node) LIST_UNLINK_PART(list,node,)
#define LIST_LINK_TAIL_PART(list,node) LIST_LINK_TAIL(list,node,)

static void vdebug(adns_state ads, const char *fmt, va_list al) {
  if (!(ads->iflags & adns_if_debug)) return;
  fputs("adns debug: ",stderr);
  vfprintf(stderr,fmt,al);
  fputc('\n',stderr);
}

static void debug(adns_state ads, const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  vdebug(ads,fmt,al);
  va_end(al);
}

static void vdiag(adns_state ads, const char *fmt, va_list al) {
  if (ads->iflags & adns_if_noerrprint) return;
  fputs("adns: ",stderr);
  vfprintf(stderr,fmt,al);
  fputc('\n',stderr);
}

static void diag(adns_state ads, const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  vdiag(ads,fmt,al);
  va_end(al);
}

static void addserver(adns_state ads, struct in_addr addr) {
  int i;
  struct server *ss;
  
  for (i=0; i<ads->nservers; i++) {
    if (ads->servers[i].addr.s_addr == addr.s_addr) {
      debug(ads,"duplicate nameserver %s ignored",inet_ntoa(addr));
      return;
    }
  }
  
  if (ads->nservers>=MAXSERVERS) {
    diag(ads,"too many nameservers, ignoring %s",inet_ntoa(addr));
    return;
  }

  ss= ads->servers+ads->nservers;
  ss->addr= addr;
  ss->state= server_disc;
  ss->connw.head= ss->connw.tail= 0;
  ads->nservers++;
}

static void configparseerr(adns_state ads, const char *fn, int lno,
			   const char *fmt, ...) {
  va_list al;
  
  if (ads->iflags & adns_if_noerrprint) return;
  if (lno==-1) fprintf(stderr,"adns: %s: ",fn);
  else fprintf(stderr,"adns: %s:%d: ",fn,lno);
  va_start(al,fmt);
  vfprintf(stderr,fmt,al);
  va_end(al);
  fputc('\n',stderr);
}

static void ccf_nameserver(adns_state ads, const char *fn, int lno, const char *buf) {
  struct in_addr ia;
  
  if (!inet_aton(buf,&ia)) {
    configparseerr(ads,fn,lno,"invalid nameserver address `%s'",buf);
    return;
  }
  debug(ads,"using nameserver %s",inet_ntoa(ia));
  addserver(ads,ia);
}

static void ccf_search(adns_state ads, const char *fn, int lno, const char *buf) {
  if (!buf) return;
  diag(ads,"warning - `search' ignored FIXME");
}

static void ccf_sortlist(adns_state ads, const char *fn, int lno, const char *buf) {
  diag(ads,"warning - `sortlist' ignored FIXME");
}

static void ccf_options(adns_state ads, const char *fn, int lno, const char *buf) {
  if (!buf) return;
  diag(ads,"warning - `options' ignored FIXME");
}

static void ccf_clearnss(adns_state ads, const char *fn, int lno, const char *buf) {
  ads->nservers= 0;
}

static const struct configcommandinfo {
  const char *name;
  void (*fn)(adns_state ads, const char *fn, int lno, const char *buf);
} configcommandinfos[]= {
  { "nameserver",        ccf_nameserver  },
  { "domain",            ccf_search      },
  { "search",            ccf_search      },
  { "sortlist",          ccf_sortlist    },
  { "options",           ccf_options     },
  { "clearnameservers",  ccf_clearnss    },
  {  0                                   }
};

static int ctype_whitespace(int c) { return c==' ' || c=='\n' || c=='\t'; }
static int ctype_digit(int c) { return c>='0' && c<='9'; }

static void readconfig(adns_state ads, const char *filename) {
  char linebuf[2000], *p, *q;
  FILE *file;
  int lno, l, c;
  const struct configcommandinfo *ccip;

  file= fopen(filename,"r");
  if (!file) {
    if (errno == ENOENT) {
      debug(ads,"configuration file `%s' does not exist",filename);
      return;
    }
    diag(ads,"cannot open configuration file `%s': %s",filename,strerror(errno));
    return;
  }

  for (lno=1; fgets(linebuf,sizeof(linebuf),file); lno++) {
    l= strlen(linebuf);
    if (!l) continue;
    if (linebuf[l-1] != '\n' && !feof(file)) {
      diag(ads,"%s:%d: line too long",filename,lno);
      while ((c= getc(file)) != EOF && c != '\n') { }
      if (c == EOF) break;
      continue;
    }
    while (l>0 && ctype_whitespace(linebuf[l-1])) l--;
    linebuf[l]= 0;
    p= linebuf;
    while (ctype_whitespace(*p)) p++;
    if (*p == '#' || *p == '\n') continue;
    q= p;
    while (*q && !ctype_whitespace(*q)) q++;
    for (ccip=configcommandinfos;
	 ccip->name && strncmp(ccip->name,p,q-p);
	 ccip++);
    if (!ccip->name) {
      diag(ads,"%s:%d: unknown configuration directive `%.*s'",filename,lno,q-p,p);
      continue;
    }
    while (ctype_whitespace(*q)) q++;
    ccip->fn(ads,filename,lno,q);
  }
  if (ferror(file)) {
    diag(ads,"%s:%d: read error: %s",filename,lno,strerror(errno));
  }
  fclose(file);
}

static const char *instrum_getenv(adns_state ads, const char *envvar) {
  const char *value;

  value= getenv(envvar);
  if (!value) debug(ads,"environment variable %s not set",envvar);
  else debug(ads,"environment variable %s set to `%s'",envvar,value);
  return value;
}

static void readconfigenv(adns_state ads, const char *envvar) {
  const char *filename;

  if (ads->iflags & adns_if_noenv) {
    debug(ads,"not checking environment variable `%s'",envvar);
    return;
  }
  filename= instrum_getenv(ads,envvar);
  if (filename) readconfig(ads,filename);
}
  
int adns_init(adns_state *ads_r, adns_initflags flags) {
  adns_state ads;
  const char *res_options, *adns_res_options;
  struct protoent *proto;
  int r;
  
  ads= malloc(sizeof(*ads)); if (!ads) return errno;
  ads->tosend.head= ads->tosend.tail= 0;
  ads->timew.head= ads->timew.tail= 0;
  ads->childw.head= ads->childw.tail= 0;
  ads->output.head= ads->output.tail= 0;
  ads->nextid= 0x311f;
  ads->udpsocket= -1;
  ads->qbufavail= 0;
  ads->qbuf= 0;
  ads->tcpbufavail= ads->tcpbufused= ads->tcpbufdone= 0;
  ads->tcpbuf= 0;
  ads->iflags= flags;
  ads->nservers= 0;
  ads->iflags= flags;

  res_options= instrum_getenv(ads,"RES_OPTIONS");
  adns_res_options= instrum_getenv(ads,"ADNS_RES_OPTIONS");
  ccf_options(ads,"RES_OPTIONS",-1,res_options);
  ccf_options(ads,"ADNS_RES_OPTIONS",-1,adns_res_options);

  readconfig(ads,"/etc/resolv.conf");
  readconfigenv(ads,"RES_CONF");
  readconfigenv(ads,"ADNS_RES_CONF");

  ccf_options(ads,"RES_OPTIONS",-1,res_options);
  ccf_options(ads,"ADNS_RES_OPTIONS",-1,adns_res_options);

  ccf_search(ads,"LOCALDOMAIN",-1,instrum_getenv(ads,"LOCALDOMAIN"));
  ccf_search(ads,"ADNS_LOCALDOMAIN",-1,instrum_getenv(ads,"ADNS_LOCALDOMAIN"));

  if (!ads->nservers) {
    struct in_addr ia;
    if (ads->iflags & adns_if_debug)
      fprintf(stderr,"adns: no nameservers, using localhost\n");
    ia.s_addr= INADDR_LOOPBACK;
    addserver(ads,ia);
  }

  proto= getprotobyname("udp"); if (!proto) { r= ENOPROTOOPT; goto x_free; }
  ads->udpsocket= socket(AF_INET,SOCK_DGRAM,proto->p_proto);
  if (!ads->udpsocket) { r= errno; goto x_closeudp; }
  
  *ads_r= ads;
  return 0;

 x_closeudp:
  close(ads->udpsocket);
 x_free:
  free(ads);
  return r;
}

static void query_fail(adns_state ads, adns_query qu, adns_status stat) {
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

int adns_finish(adns_state ads) {
  abort(); /* FIXME */
}

static void autosys(adns_state ads, struct timeval now) {
  if (ads->iflags & adns_if_noautosys) return;
  adns_callback(ads,-1,0,0,0);
}

void adns_cancel(adns_state ads, adns_query query) {
  abort(); /* FIXME */
}

int adns_callback(adns_state ads, int maxfd,
		  const fd_set *readfds, const fd_set *writefds,
		  const fd_set *exceptfds) {
  abort(); /* FIXME */
}

static void inter_maxto(struct timeval **tv_io, struct timeval *tvbuf,
			struct timeval maxto) {
  struct timeval rbuf;

  rbuf= *tv_io;
  if (!rbuf) { *tvbuf= maxto; *tv_io= tvbuf; return; }
  if (timercmp(rbuf,&maxto,>)) *rbuf= maxto;
}

static void inter_maxtoabs(struct timeval **tv_io, struct timeval *tvbuf,
			   struct timeval now, struct timeval maxtime) {
  ldiv_t dr;
  
  maxtime.tv_sec -= (now.tv_sec-1);
  maxtime.tv_usec += (1000-now.tv_usec);
  dr= ldiv(maxtime.tv_usec,1000);
  maxtime.tv_sec += dr.quot;
  maxtime.tv_usec -= dr.rem;
  inter_maxto(tv_io,tvbuf,maxtime);
}

static void localresourcerr(struct timeval **tv_io, struct timeval *tvbuf,
			    const char *syscall) {
  struct timeval tvto_lr;
  
  diag(ads,"local system resources scarce (during %s): %s",syscall,strerror(errno));
  timerclear(&tvto_lr); timevaladd(&tvto_lr,LOCALRESOURCEMS);
  inter_maxto(tv_io, tvbuf, tvto_lr);
  return;
}

static inline void timevaladd(struct timeval *tv_io, long ms) {
  struct timeval tmp;
  assert(ms>=0);
  tmp= *tv_io;
  tmp.tv_usec += (ms%1000)*1000;
  tmp.tv_sec += ms/1000;
  if (tmp.tv_usec >= 1000) { tmp.tv_sec++; tmp.tv_usec -= 1000; }
  *tv_io= tmp;
}    

void adns_interest(adns_state ads, int *maxfd,
		   fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		   struct timeval **tv_io, struct timeval *tvbuf) {
  struct timeval now;
  adns_query qu;
  int r;
  
  r= gettimeofday(&now,0);
  if (r) { localresourcerr(tv_io,tvbuf,"gettimeofday"); return; }

  for (qu= ads->timew; qu; qu= nqu) {
    nqu= qu->next;
    if (timercmp(&now,qu->timeout,>)) {
      DLIST_UNLINK(ads->timew,qu);
      if (qu->nextudpserver == -1) {
	query_fail(ads,qu,adns_s_notresponding);
      } else {
	DLIST_LINKTAIL(ads->tosend,qu);
      }
    } else {
      inter_maxtoabs(tv_io,tvbuf,now,qu->timeout);
    }
  }
  
  for (qu= ads->tosend; qu; qu= nqu) {
    nqu= qu->next;
    quproc_tosend(ads,qu,now);
  }

  for (qu= ads->timew; qu; qu= qu->next) {
    if (qu->sentudp) {
      inter_addfd(maxfd,readfds,ads->udpsocket);
      break;
    }
  }
  switch (ads->tcpstate) {
  case server_disc:
    break;
  case server_connecting:
    inter_addfd(maxfd,readfds,ads->tcpsocket);
    inter_addfd(maxfd,writefds,ads->tcpsocket);
    inter_addfd(maxfd,exceptfds,ads->tcpsocket);
    break;
  case server_connected:
    inter_addfd(maxfd,readfds,ads->tcpsocket);
    inter_addfd(maxfd,exceptfds,ads->tcpsocket);
    if (ads->opbufused) inter_addfd(maxfd,writefds,ads->tcpsocket);
  default:
    abort();
  }
  
}

static int internal_check(adns_state ads,
			  adns_query *query_io,
			  adns_answer **answer,
			  void **context_r) {
  adns_query qu;

  qu= *query_io;
  if (!qu) {
    if (!ads->output.head) return EWOULDBLOCK;
    qu= ads->output.head;
  } else {
    if (qu->id>=0) return EWOULDBLOCK;
  }
  LIST_UNLINK(ads->output,qu);
  *answer= qu->answer;
  if (context_r) *context_r= qu->context;
  free(qu);
  return 0;
}

int adns_wait(adns_state ads,
	      adns_query *query_io,
	      adns_answer **answer_r,
	      void **context_r) {
  int r, maxfd, rsel, rcb;
  fd_set readfds, writefds, exceptfds;
  struct timeval tvbuf, *tvp;
  
  for (;;) {
    r= internal_check(ads,query_io,answer_r,context_r);
    if (r && r != EWOULDBLOCK) return r;
    FD_ZERO(&readfds); FD_ZERO(&writefds); FD_ZERO(&exceptfds);
    maxfd= 0; tvp= 0;
    adns_interest(ads,&maxfd,&readfds,&writefds,&exceptfds,&tvp,&tvbuf);
    rsel= select(maxfd,&readfds,&writefds,&exceptfds,tvp);
    if (rsel==-1) return r;
    rcb= adns_callback(ads,maxfd,&readfds,&writefds,&exceptfds);
    assert(rcb==rsel);
  }
}

int adns_check(adns_state ads,
	       adns_query *query_io,
	       adns_answer **answer_r,
	       void **context_r) {
  autosys(ads);
  return internal_check(ads,query_io,answer_r,context_r);
}

int adns_synchronous(adns_state ads,
		     const char *owner,
		     adns_rrtype type,
		     adns_queryflags flags,
		     adns_answer **answer_r) {
  adns_query qu;
  int r;
  
  r= adns_submit(ads,owner,type,flags,0,&qu);
  if (r) return r;

  do {
    r= adns_wait(ads,&qu,answer_r,0);
  } while (r==EINTR);
  if (r) adns_cancel(ads,qu);
  return r;
}

static adns_status mkquery(adns_state ads, const char *owner, int ol, int id,
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
	if ((c >= '0' && c <= '9') || c == '-') {
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

static adns_query allocquery(adns_state ads, const char *owner, int ol,
			     int qml, int id, adns_rrtype type,
			     adns_queryflags flags, void *context) {
  adns_query qu;
  unsigned char *qm;
  
  qu= malloc(sizeof(*qu)+ol+1+qml); if (!qu) return 0;
  qu->next= qu->back= qu->parent= 0;
  qu->children.head= qu->children.tail= 0;
  qu->siblings.next= qu->siblings.back= 0;
  qu->id= id;
  qu->type= type;
  qu->answer= 0;
  qu->flags= flags;
  qu->context= context;
  qu->udpretries= 0;
  qu->sentudp= qu->senttcp= 0;
  qu->nextserver= 0;
  memcpy(qu->owner,owner,ol); qu->owner[ol]= 0;
  qu->querymsg= qm= qu->owner+ol+1;
  memcpy(qm,ads->qbuf,qml);
  qu->querylen= qml;
  return qu;
}

static int failsubmit(adns_state ads, void *context, adns_query *query_r,
		      adns_rrtype type, adns_queryflags flags,
		      int id, adns_status stat) {
  adns_query qu;

  qu= allocquery(ads,0,0,0,id,type,flags,context); if (!qu) return errno;
  query_fail(ads,qu,stat);
  *query_r= qu;
  return 0;
}

static void quproc_tosend(adns_state ads, adns_query qu, struct timeval now) {
  /* Query must be on the `tosend' queue, and guarantees to remove it. */
  struct sockaddr_in servaddr;
  int serv;

  if (qu->nextudpserver != -1) {
    if (qu->udpretries >= UDPMAXRETRIES) {
      DLIST_UNLINK(ads->tosend,qu);
      query_fail(ads,qu,adns_s_notresponding);
      return;
    }
    serv= qu->nextudpserver;
    memset(&servaddr,0,sizeof(servaddr));
    servaddr.sin_family= AF_INET;
    servaddr.sin_addr= ads->servers[serv].addr;
    servaddr.sin_port= htons(53);
    r= sendto(ads->udpsocket,qu->querymsg,qu->querylen,0,&servaddr,sizeof(servaddr));
    if (r<0 && errno == EMSGSIZE) {
      qu->nextudpserver= -1;
    } else {
      if (r<0) {
	diag("sendto %s failed: %s",inet_ntoa(servaddr.sin_addr),strerror(errno));
      }
      DLIST_UNLINK(ads->tosend,qu);
      timevaladd(&now,UDPRETRYMS);
      qu->timeout= now;
      qu->sentudp |= (1<<serv);
      qu->nextudpserver= (serv+1)%ads->nservers;
      qu->udpretries++;
      DLIST_LINKTAIL(ads->timew,qu);
      return;
    }
  }

  for (;;) {
    serv= tcpserver_get(ads);
    if (serv<0) { r=0; break; }
    if (ads->opbufused) { r=0; break; }
    r= write(ads->tcpsocket,qu->querymsg,qu->querylen);
    if (r >= 0) break;
    if (errno == EAGAIN || errno == EINTR || errno == ENOSPC ||
	errno == ENOBUFS || errno == ENOMEM) {
      r= 0; break;
    }
    tcpserver_broken(serv);
  }
  if (r < qu->querylen) {
    newopbufused= qu->opbufused + (qu->querylen-r);
    if (newopbufused > ads->opbufavail) {
      newopbufavail= ads->newopbufused<<1;
      newopbuf= realloc(newopbufavail);
      if (!newopbuf) {
	DLIST_UNLINK(ads->tosend,qu);
	query_fail(ads,qu,adns_s_nolocalmem);
	return;
      }
      ads->opbuf= newopbuf;
      ads->opbufavail= newopbufavail;
    }
    memcpy(ads->opbuf+ads->opbufused,qu->querymsg+r,qu->querylen-r);
    ads->opbufused= newopbufused;
  }
  DLIST_UNLINK(ads->tosend,qu);
  timevaladd(&now,TCPMS);
  qu->timeout= now;
  qu->senttcp |= (1<<qu->nextserver);
  DLIST_LINKTAIL(ads->timew,qu);
}

int adns_submit(adns_state ads,
		const char *owner,
		adns_rrtype type,
		adns_queryflags flags,
		void *context,
		adns_query *query_r) {
  adns_query qu;
  adns_status stat;
  int ol, id, qml;

  id= ads->nextid++;

  ol= strlen(owner);
  if (ol<=1 || ol>MAXDNAME+1)
    return failsubmit(ads,context,query_r,type,flags,id,adns_s_invaliddomain);
  if (owner[ol-1]=='.' && owner[ol-2]!='\\') { flags &= ~adns_f_search; ol--; }

  stat= mkquery(ads,owner,ol,id,type,flags,&qml);
  if (stat) return failsubmit(ads,context,query_r,type,flags,id,stat);

  qu= allocquery(ads,owner,ol,qml,id,type,flags,context); if (!qu) return errno;
  if (qu->flags & adns_f_usevc) qu->udpretries= -1;
  LIST_LINK_TAIL(ads->tosend,qu);
    
  r= gettimeofday(&now,0); if (r) return;
  quproc_tosend(ads,qu,now);
  autosys(ads,now);

  *query_r= qu;
  return 0;
}
