/*
 * setup.c
 * - configuration file parsing
 * - management of global state
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
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <netdb.h>
#include <arpa/inet.h>

#include "internal.h"

static void readconfig(adns_state ads, const char *filename);

static void addserver(adns_state ads, struct in_addr addr) {
  int i;
  struct server *ss;
  
  for (i=0; i<ads->nservers; i++) {
    if (ads->servers[i].addr.s_addr == addr.s_addr) {
      adns__debug(ads,-1,0,"duplicate nameserver %s ignored",inet_ntoa(addr));
      return;
    }
  }
  
  if (ads->nservers>=MAXSERVERS) {
    adns__diag(ads,-1,0,"too many nameservers, ignoring %s",inet_ntoa(addr));
    return;
  }

  ss= ads->servers+ads->nservers;
  ss->addr= addr;
  ads->nservers++;
}

static void saveerr(adns_state ads, int en) {
  if (!ads->configerrno) ads->configerrno= en;
}

static void configparseerr(adns_state ads, const char *fn, int lno,
			   const char *fmt, ...) {
  va_list al;

  saveerr(ads,EINVAL);
  if (!ads->diagfile || (ads->iflags & adns_if_noerrprint)) return;

  if (lno==-1) fprintf(ads->diagfile,"adns: %s: ",fn);
  else fprintf(ads->diagfile,"adns: %s:%d: ",fn,lno);
  va_start(al,fmt);
  vfprintf(ads->diagfile,fmt,al);
  va_end(al);
  fputc('\n',ads->diagfile);
}

static void ccf_nameserver(adns_state ads, const char *fn, int lno, const char *buf) {
  struct in_addr ia;
  
  if (!inet_aton(buf,&ia)) {
    configparseerr(ads,fn,lno,"invalid nameserver address `%s'",buf);
    return;
  }
  adns__debug(ads,-1,0,"using nameserver %s",inet_ntoa(ia));
  addserver(ads,ia);
}

static void ccf_search(adns_state ads, const char *fn, int lno, const char *buf) {
  if (!buf) return;
  adns__diag(ads,-1,0,"warning - `search' ignored fixme");
}

static void ccf_sortlist(adns_state ads, const char *fn, int lno, const char *buf) {
  adns__diag(ads,-1,0,"warning - `sortlist' ignored fixme");
}

static void ccf_options(adns_state ads, const char *fn, int lno, const char *buf) {
  if (!buf) return;
  adns__diag(ads,-1,0,"warning - `options' ignored fixme");
}

static void ccf_clearnss(adns_state ads, const char *fn, int lno, const char *buf) {
  ads->nservers= 0;
}

static void ccf_include(adns_state ads, const char *fn, int lno, const char *buf) {
  if (!*buf) {
    configparseerr(ads,fn,lno,"`include' directive with no filename");
    return;
  }
  readconfig(ads,buf);
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
  { "include",           ccf_include     },
  {  0                                   }
};

typedef union {
  FILE *file;
  const char *text;
} getline_ctx;

static int gl_file(adns_state ads, getline_ctx *src_io, const char *filename,
		   int lno, char *buf, int buflen) {
  FILE *file= src_io->file;
  int c, i;
  char *p;

  p= buf;
  buflen--;
  i= 0;
    
  for (;;) { /* loop over chars */
    if (i == buflen) {
      adns__diag(ads,-1,0,"%s:%d: line too long, ignored",filename,lno);
      goto x_badline;
    }
    c= getc(file);
    if (!c) {
      adns__diag(ads,-1,0,"%s:%d: line contains nul, ignored",filename,lno);
      goto x_badline;
    } else if (c == '\n') {
      break;
    } else if (c == EOF) {
      if (ferror(file)) {
	saveerr(ads,errno);
	adns__diag(ads,-1,0,"%s:%d: read error: %s",filename,lno,strerror(errno));
	return -1;
      }
      if (!i) return -1;
      break;
    } else {
      *p++= c;
      i++;
    }
  }

  *p++= 0;
  return i;

 x_badline:
  saveerr(ads,EINVAL);
  while ((c= getc(file)) != EOF && c != '\n');
  return -2;
}

static int gl_text(adns_state ads, getline_ctx *src_io, const char *filename,
		   int lno, char *buf, int buflen) {
  const char *cp= src_io->text, *nn;
  int l;

  if (!cp) return -1;
  
  nn= strchr(cp,'\n');

  l= nn ? nn-cp : strlen(cp);
  src_io->text= nn ? nn+1 : 0;

  if (l >= buflen) {
    adns__diag(ads,-1,0,"%s:%d: line too long, ignored",filename,lno);
    saveerr(ads,EINVAL);
    return -2;
  }
    
  memcpy(buf,cp,l);
  buf[l]= 0;
  return l;
}

static void readconfiggeneric(adns_state ads, const char *filename,
			      int (*getline)(adns_state ads, getline_ctx*,
					     const char *filename, int lno,
					     char *buf, int buflen),
			      /* Returns >=0 for success, -1 for EOF or error
			       * (error will have been reported), or -2 for
			       * bad line was encountered, try again.
			       */
			      getline_ctx gl_ctx) {
  char linebuf[2000], *p, *q;
  int lno, l, dirl;
  const struct configcommandinfo *ccip;

  for (lno=1;
       (l= getline(ads,&gl_ctx, filename,lno, linebuf,sizeof(linebuf))) != -1;
       lno++) {
    if (l == -2) continue;
    while (l>0 && ctype_whitespace(linebuf[l-1])) l--;
    linebuf[l]= 0;
    p= linebuf;
    while (ctype_whitespace(*p)) p++;
    if (*p == '#' || !*p) continue;
    q= p;
    while (*q && !ctype_whitespace(*q)) q++;
    dirl= q-p;
    for (ccip=configcommandinfos;
	 ccip->name && !(strlen(ccip->name)==dirl && !memcmp(ccip->name,p,q-p));
	 ccip++);
    if (!ccip->name) {
      adns__diag(ads,-1,0,"%s:%d: unknown configuration directive `%.*s'",
		 filename,lno,q-p,p);
      continue;
    }
    while (ctype_whitespace(*q)) q++;
    ccip->fn(ads,filename,lno,q);
  }
}

static const char *instrum_getenv(adns_state ads, const char *envvar) {
  const char *value;

  value= getenv(envvar);
  if (!value) adns__debug(ads,-1,0,"environment variable %s not set",envvar);
  else adns__debug(ads,-1,0,"environment variable %s set to `%s'",envvar,value);
  return value;
}

static void readconfig(adns_state ads, const char *filename) {
  getline_ctx gl_ctx;
  
  gl_ctx.file= fopen(filename,"r");
  if (!gl_ctx.file) {
    if (errno == ENOENT) {
      adns__debug(ads,-1,0,"configuration file `%s' does not exist",filename);
      return;
    }
    saveerr(ads,errno);
    adns__diag(ads,-1,0,"cannot open configuration file `%s': %s",
	       filename,strerror(errno));
    return;
  }

  readconfiggeneric(ads,filename,gl_file,gl_ctx);
  
  fclose(gl_ctx.file);
}

static void readconfigtext(adns_state ads, const char *text, const char *showname) {
  getline_ctx gl_ctx;
  
  gl_ctx.text= text;
  readconfiggeneric(ads,showname,gl_text,gl_ctx);
}
  
static void readconfigenv(adns_state ads, const char *envvar) {
  const char *filename;

  if (ads->iflags & adns_if_noenv) {
    adns__debug(ads,-1,0,"not checking environment variable `%s'",envvar);
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

static int init_begin(adns_state *ads_r, adns_initflags flags, FILE *diagfile) {
  adns_state ads;
  
  ads= malloc(sizeof(*ads)); if (!ads) return errno;

  ads->iflags= flags;
  ads->diagfile= diagfile;
  LIST_INIT(ads->timew);
  LIST_INIT(ads->childw);
  LIST_INIT(ads->output);
  ads->nextid= 0x311f;
  ads->udpsocket= ads->tcpsocket= -1;
  adns__vbuf_init(&ads->tcpsend);
  adns__vbuf_init(&ads->tcprecv);
  ads->nservers= ads->tcpserver= 0;
  ads->tcpstate= server_disconnected;
  timerclear(&ads->tcptimeout);

  *ads_r= ads;
  return 0;
}

static int init_finish(adns_state ads) {
  struct in_addr ia;
  struct protoent *proto;
  int r;
  
  if (!ads->nservers) {
    if (ads->diagfile && ads->iflags & adns_if_debug)
      fprintf(ads->diagfile,"adns: no nameservers, using localhost\n");
    ia.s_addr= INADDR_LOOPBACK;
    addserver(ads,ia);
  }

  proto= getprotobyname("udp"); if (!proto) { r= ENOPROTOOPT; goto x_free; }
  ads->udpsocket= socket(AF_INET,SOCK_DGRAM,proto->p_proto);
  if (ads->udpsocket<0) { r= errno; goto x_free; }

  r= adns__setnonblock(ads,ads->udpsocket);
  if (r) { r= errno; goto x_closeudp; }
  
  return 0;

 x_closeudp:
  close(ads->udpsocket);
 x_free:
  free(ads);
  return r;
}

int adns_init(adns_state *ads_r, adns_initflags flags, FILE *diagfile) {
  adns_state ads;
  const char *res_options, *adns_res_options;
  int r;
  
  r= init_begin(&ads, flags, diagfile ? diagfile : stderr);
  if (r) return r;
  
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

  r= init_finish(ads);
  if (r) return r;

  *ads_r= ads;
  return 0;
}

int adns_init_strcfg(adns_state *ads_r, adns_initflags flags,
		     FILE *diagfile, const char *configtext) {
  adns_state ads;
  int r;

  r= init_begin(&ads, flags, diagfile);  if (r) return r;

  readconfigtext(ads,configtext,"<supplied configuration text>");
  if (ads->configerrno) {
    r= ads->configerrno;
    free(ads);
    return r;
  }

  r= init_finish(ads);  if (r) return r;
  *ads_r= ads;
  return 0;
}

void adns_finish(adns_state ads) {
  for (;;) {
    if (ads->timew.head) adns_cancel(ads->timew.head);
    else if (ads->childw.head) adns_cancel(ads->childw.head);
    else if (ads->output.head) adns_cancel(ads->output.head);
    else break;
  }
  close(ads->udpsocket);
  if (ads->tcpsocket >= 0) close(ads->tcpsocket);
  adns__vbuf_free(&ads->tcpsend);
  adns__vbuf_free(&ads->tcprecv);
  free(ads);
}
