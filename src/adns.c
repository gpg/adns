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

#define LIST_UNLINK(list,node) \
  do { \
    if ((node)->back) (node)->back->next= (node)->next; \
      else                   (list).head= (node)->next; \
    if ((node)->next) (node)->next->back= (node)->back; \
      else                   (list).tail= (node)->back; \
  } while(0)

#define LIST_LINK_TAIL(list,node) \
  do { \
    (node)->back= 0; \
    (node)->next= (list).tail; \
    if ((list).tail) (list).tail->back= (node); else (list).head= (node); \
    (list).tail= (node); \
  } while(0)

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

static int whitespace(int c) {
  return c==' ' || c=='\n' || c=='\t';
}

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
    while (l>0 && whitespace(linebuf[l-1])) l--;
    linebuf[l]= 0;
    p= linebuf;
    while (whitespace(*p)) p++;
    if (*p == '#' || *p == '\n') continue;
    q= p;
    while (*q && !whitespace(*q)) q++;
    for (ccip=configcommandinfos;
	 ccip->name && strncmp(ccip->name,p,q-p);
	 ccip++);
    if (!ccip->name) {
      diag(ads,"%s:%d: unknown configuration directive `%.*s'",filename,lno,q-p,p);
      continue;
    }
    while (whitespace(*q)) q++;
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
  struct sockaddr_in udpaddr;
  int udpaddrlen, r;
  
  ads= malloc(sizeof(*ads)); if (!ads) return errno;
  ads->input.head= ads->input.tail= 0;
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

  memset(&udpaddr,0,sizeof(udpaddr));
  udpaddr.sin_family= AF_INET;
  udpaddr.sin_addr.s_addr= INADDR_ANY;
  udpaddr.sin_port= 0;
  r= bind(ads->udpsocket,&udpaddr,sizeof(udpaddr));
  if (r) { r= errno; goto x_closeudp; }

  udpaddrlen= sizeof(udpaddr);
  r= getsockname(ads->udpsocket,&udpaddr,&udpaddrlen);
  if (r) { r= errno; goto x_closeudp; }
  if (udpaddr.sin_family != AF_INET) {
    diag(ads,"network API error: UDP socket not AF_INET but %lu",
	 (unsigned long)udpaddr.sin_family);
    r= EPROTOTYPE; goto x_closeudp;
  }
  debug(ads,"UDP socket is %s:%u",inet_ntoa(udpaddr.sin_addr),ntohs(udpaddr.sin_port));
  
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
  LIST_LINK_TAIL(ads->input,qu);
}

int adns_finish(adns_state ads) {
  abort(); /* FIXME */
}

void adns_interest(adns_state ads, int *maxfd,
		   fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		   struct timeval **tv_io, struct timeval *tvbuf) {
  abort(); /* FIXME */
}

static void autosys(adns_state ads) {
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

static int internal_check(adns_state ads,
			  adns_query *query_io,
			  adns_answer *answer,
			  void *context_r) {
  abort(); /* FIXME */
}

int adns_wait(adns_state ads,
	      adns_query *query_io,
	      adns_answer *answer,
	      void *context_r) {
  int r, maxfd, rsel, rcb;
  fd_set readfds, writefds, exceptfds;
  struct timeval tvbuf, *tvp;
  
  for (;;) {
    r= internal_check(ads,query_io,answer,context_r);
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
	       adns_answer *answer,
	       void *context_r) {
  autosys(ads);
  return internal_check(ads,query_io,answer,context_r);
}

int adns_synchronous(adns_state ads,
		     const char *owner,
		     adns_rrtype type,
		     adns_queryflags flags,
		     adns_answer *answer) {
  adns_query qu;
  int r;
  
  r= adns_submit(ads,owner,type,flags,0,&qu);
  if (r) return r;

  do {
    r= adns_wait(ads,&qu,answer,0);
  } while (r==EINTR);
  if (r) adns_cancel(ads,qu);
  return r;
}

static int mkquery(adns_state ads,
		   const char *owner,
		   adns_rrtype type) {
  abort();
}

int adns_submit(adns_state ads,
		const char *owner,
		adns_rrtype type,
		adns_queryflags flags,
		void *context,
		adns_query *query_r) {
  adns_query qu;
  adns_status stat;
  int ol;

  stat= 0;
  ol= strlen(owner);
  if (ol>MAXDNAME+1) { stat= adns_s_invaliddomain; ol= 0; }
  if (ol>0 && owner[ol-1]=='.') { flags &= ~adns_f_search; ol--; }
  qu= malloc(sizeof(*qu)+ol+1); if (!qu) return errno;
  qu->next= qu->back= qu->parent= qu->child= 0;
  qu->id= ads->nextid++;
  qu->type= type;
  qu->answer= 0;
  qu->flags= flags;
  qu->context= context;
  qu->udpretries= 0;
  qu->sentudp= qu->senttcp= 0;
  qu->nextserver= 0;
  memcpy(qu->owner,owner,ol); qu->owner[ol]= 0;


  mkquery(ads,owner,type);

  if (stat) {
    query_fail(ads,qu,stat);
  } else {
    LIST_LINK_TAIL(ads->input,qu);
    autosys(ads);
  }
  *query_r= qu;
  return 0;
}
