/**/

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <netdb.h>
#include <arpa/inet.h>

#include "internal.h"

void adns__vdiag(adns_state ads, const char *pfx, adns_initflags prevent,
		 int serv, const char *fmt, va_list al) {
  if (!(ads->iflags & adns_if_debug) && (!prevent || (ads->iflags & prevent))) return;
  if (serv>=0) {
    fprintf(stderr,"adns%s: nameserver %s: ",pfx,inet_ntoa(ads->servers[serv].addr));
  } else {
    fprintf(stderr,"adns%s: ",pfx);
  }
  vfprintf(stderr,fmt,al);
  fputc('\n',stderr);
}

void adns__debug(adns_state ads, int serv, const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  adns__vdiag(ads," debug",0,serv,fmt,al);
  va_end(al);
}

void adns__warn(adns_state ads, int serv, const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  adns__vdiag(ads," warning",adns_if_noerrprint|adns_if_noserverwarn,serv,fmt,al);
  va_end(al);
}

void adns__diag(adns_state ads, int serv, const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  adns__vdiag(ads,"",adns_if_noerrprint,serv,fmt,al);
  va_end(al);
}

  
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
    newlen <<= 1;
    nb= realloc(vb->buf,newlen);
    if (!nb) { newlen >>= 1; nb= realloc(vb->buf,newlen); }
    if (!nb) return 0;
    vb->buf= nb;
    vb->avail= newlen;
  }
  adns__vbuf_appendq(vb,data,len);
  return 1;
}


static void addserver(adns_state ads, struct in_addr addr) {
  int i;
  struct server *ss;
  
  for (i=0; i<ads->nservers; i++) {
    if (ads->servers[i].addr.s_addr == addr.s_addr) {
      adns__debug(ads,-1,"duplicate nameserver %s ignored",inet_ntoa(addr));
      return;
    }
  }
  
  if (ads->nservers>=MAXSERVERS) {
    adns__diag(ads,-1,"too many nameservers, ignoring %s",inet_ntoa(addr));
    return;
  }

  ss= ads->servers+ads->nservers;
  ss->addr= addr;
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
  adns__debug(ads,-1,"using nameserver %s",inet_ntoa(ia));
  addserver(ads,ia);
}

static void ccf_search(adns_state ads, const char *fn, int lno, const char *buf) {
  if (!buf) return;
  adns__diag(ads,-1,"warning - `search' ignored fixme");
}

static void ccf_sortlist(adns_state ads, const char *fn, int lno, const char *buf) {
  adns__diag(ads,-1,"warning - `sortlist' ignored fixme");
}

static void ccf_options(adns_state ads, const char *fn, int lno, const char *buf) {
  if (!buf) return;
  adns__diag(ads,-1,"warning - `options' ignored fixme");
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

static void readconfig(adns_state ads, const char *filename) {
  char linebuf[2000], *p, *q;
  FILE *file;
  int lno, l, c;
  const struct configcommandinfo *ccip;

  file= fopen(filename,"r");
  if (!file) {
    if (errno == ENOENT) {
      adns__debug(ads,-1,"configuration file `%s' does not exist",filename);
      return;
    }
    adns__diag(ads,-1,"cannot open configuration file `%s': %s",
	       filename,strerror(errno));
    return;
  }

  for (lno=1; fgets(linebuf,sizeof(linebuf),file); lno++) {
    l= strlen(linebuf);
    if (!l) continue;
    if (linebuf[l-1] != '\n' && !feof(file)) {
      adns__diag(ads,-1,"%s:%d: line too long",filename,lno);
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
      adns__diag(ads,-1,"%s:%d: unknown configuration directive `%.*s'",
		 filename,lno,q-p,p);
      continue;
    }
    while (ctype_whitespace(*q)) q++;
    ccip->fn(ads,filename,lno,q);
  }
  if (ferror(file)) {
    adns__diag(ads,-1,"%s:%d: read error: %s",filename,lno,strerror(errno));
  }
  fclose(file);
}

static const char *instrum_getenv(adns_state ads, const char *envvar) {
  const char *value;

  value= getenv(envvar);
  if (!value) adns__debug(ads,-1,"environment variable %s not set",envvar);
  else adns__debug(ads,-1,"environment variable %s set to `%s'",envvar,value);
  return value;
}

static void readconfigenv(adns_state ads, const char *envvar) {
  const char *filename;

  if (ads->iflags & adns_if_noenv) {
    adns__debug(ads,-1,"not checking environment variable `%s'",envvar);
    return;
  }
  filename= instrum_getenv(ads,envvar);
  if (filename) readconfig(ads,filename);
}


int adns__setnonblock(adns_state ads, int fd) {
  int r;
  
  r= fcntl(fd,F_GETFL,0); if (r<0) return errno;
  r |= O_NONBLOCK;
  r= fcntl(fd,F_SETFL,r); if (r<0) return errno;
  return 0;
}

int adns_init(adns_state *ads_r, adns_initflags flags, FILE *diagfile) {
  adns_state ads;
  const char *res_options, *adns_res_options;
  struct protoent *proto;
  int r;
  
  ads= malloc(sizeof(*ads)); if (!ads) return errno;
  ads->iflags= flags;
  ads->diagfile= diagfile ? diagfile : stderr;
  LIST_INIT(ads->timew);
  LIST_INIT(ads->childw);
  LIST_INIT(ads->output);
  ads->nextid= 0x311f;
  ads->udpsocket= ads->tcpsocket= -1;
  adns__vbuf_init(&ads->rqbuf);
  adns__vbuf_init(&ads->tcpsend);
  adns__vbuf_init(&ads->tcprecv);
  ads->nservers= ads->tcpserver= 0;
  ads->tcpstate= server_disconnected;
  timerclear(&ads->tcptimeout);

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
  if (ads->udpsocket<0) { r= errno; goto x_free; }

  r= adns__setnonblock(ads,ads->udpsocket);
  if (r) { r= errno; goto x_closeudp; }
  
  *ads_r= ads;
  return 0;

 x_closeudp:
  close(ads->udpsocket);
 x_free:
  free(ads);
  return r;
}

int adns_finish(adns_state ads) {
  abort(); /* fixme */
}
