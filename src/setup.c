/**/

#include "adns-internal.h"

void adns__vdiag(adns_state ads, adns_initflags prevent, const char *pfx,
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
  vdiag(ads," debug",0,serv,fmt,al);
  va_end(al);
}

void adns__swarn(adns_state ads, int serv, const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  vdiag(ads," warning",adns_if_noerrprint|adns_if_noserverwarn,serv,fmt,al);
  va_end(al);
}

void adns__diag(adns_state ads, int serv, const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  vdiag(ads,"",adns_if_noerrprint,serv,fmt,al);
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
  if (ads->udpsocket<0) { r= errno; goto x_free; }
  
  *ads_r= ads;
  return 0;

 x_free:
  free(ads);
  return r;
}

int adns_finish(adns_state ads) {
  abort(); /* FIXME */
}
