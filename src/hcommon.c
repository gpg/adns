/*
 * hcommon.c
 * - complex test harness, routines used for both record and playback
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

#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "harness.h"
#include "internal.h"

vbuf vb;
FILE *Toutputfile= 0;

const struct Terrno Terrnos[]= {
  { "EAGAIN",                    EAGAIN                       },
  { "EINPROGRESS",               EINPROGRESS                  },
  { "EINTR",                     EINTR                        },
  { "EINVAL",                    EINVAL                       },
  { "EMSGSIZE",                  EMSGSIZE                     },
  { "ENOBUFS",                   ENOBUFS                      },
  { "ENOENT",                    ENOENT                       },
  { "ENOPROTOOPT",               ENOPROTOOPT                  },
  { "ENOSPC",                    ENOSPC                       },
  { "EWOULDBLOCK",               EWOULDBLOCK                  },
  {  0,                          0                            }
};

void Qgettimeofday(void) {
  Q_str("gettimeofday()");
}

void Qselect(int n, const fd_set *rfds, const fd_set *wfds, const fd_set *efds,
	     const struct timeval *to) {
  vb.used= 0;
  Tvbf("select(%d,",n);
  Tvbfdset(n,rfds);
  Tvba(",");
  Tvbfdset(n,wfds);
  Tvba(",");
  Tvbfdset(n,efds);
  if (to) {
    Tvbf(", %ld.%06ld)",to->tv_sec,to->tv_usec);
  } else {
    Tvba(", NULL)");
  }
  Q_vb();
}

void Qsocket(int type) {
  switch (type) {
  case SOCK_STREAM: Q_str("socket(,SOCK_STREAM,)"); break;
  case SOCK_DGRAM:  Q_str("socket(,SOCK_DGRAM,)");  break;
  default: abort();
  }
}

void Qfcntl_setfl(int fd, int cmd, long arg) {
  vb.used= 0;
  Tvbf("fcntl(%d, F_SETFL, %ld)",fd,arg);
  Q_vb();
}

void Qfcntl_other(int fd, int cmd) {
  assert(cmd==F_GETFL);
  vb.used= 0;
  Tvbf("fcntl(%d, F_GETFL)",fd);
  Q_vb();
}

void Qconnect(int fd, struct sockaddr *addr, int addrlen) {
  vb.used= 0;
  Tvbf("connect(%d, ",fd);
  Tvbaddr(addr,addrlen);
  Tvba(")");
  Q_vb();
}

void Qclose(int fd) {
  vb.used= 0;
  Tvbf("close(%d)",fd);
  Q_vb();
}

void Qsendto(int fd, const void *msg, int msglen,
	     const struct sockaddr *addr, int addrlen) {
  vb.used= 0;
  Tvbf("sendto(%d,,,, ",fd);
  Tvbaddr(addr,addrlen);
  Tvba(")");
  Tvbbytes(msg,msglen);
  Q_vb();
}

void Qrecvfrom(int fd, int buflen, int addrlen) {
  vb.used= 0;
  Tvbf("recvfrom(%d,,%d,,,%d)",fd,buflen,addrlen);
  Q_vb();
}

void Qread(int fd, size_t len) {
  vb.used= 0;
  Tvbf("read(%d,,%lu)",fd,(unsigned long)len);
  Q_vb();
}
  
void Qwrite(int fd, const void *buf, size_t len) {
  vb.used= 0;
  Tvbf("write(%d,,)",fd);
  Tvbbytes(buf,len);
  Q_vb();
}


void Tvbaddr(const struct sockaddr *addr, int len) {
  const struct sockaddr_in *ai= (const struct sockaddr_in*)addr;
  
  assert(len==sizeof(struct sockaddr_in));
  assert(ai->sin_family==AF_INET);
  Tvbf(" %s:%u",inet_ntoa(ai->sin_addr),htons(ai->sin_port));
}

void Tvbbytes(const void *buf, int len) {
  const byte *bp;
  int i;

  if (!len) { Tvba(" empty"); return; }
  for (i=0, bp=buf; i<len; i++, bp++) {
    if (!(i&31)) Tvba("\n     ");
    else if (!(i&3)) Tvba(" ");
    Tvbf("%02x",*bp);
  }
}

void Tvbfdset(int max, const fd_set *fds) {
  int i;
  const char *comma= "";
  
  Tvba(" [");
  for (i=0; i<max; i++) {
    if (!FD_ISSET(i,fds)) continue;
    Tvba(comma);
    Tvbf("%d",i);
    comma= ",";
  }
  Tvba("]");
}

void Tvberrno(int e) {
  const struct Terrno *te;

  for (te= Terrnos; te->n && te->v != e; te++);
  if (te->n) Tvba(te->n);
  else Tvbf("E#%d",e);
}

void Tvba(const char *str) {
  if (!adns__vbuf_appendstr(&vb,str)) Tnomem();
}

void Tvbvf(const char *fmt, va_list al) {
  char buf[1000];
  buf[sizeof(buf)-2]= '\t';
  vsnprintf(buf,sizeof(buf),fmt,al);
  assert(buf[sizeof(buf)-2] == '\t');

  Tvba(buf);
}

void Tvbf(const char *fmt, ...) {
  va_list al;
  va_start(al,fmt);
  Tvbvf(fmt,al);
  va_end(al);
}


void Tfailed(const char *why) {
  fprintf(stderr,"adns test harness: failure: %s: %s\n",why,strerror(errno));
  exit(-1);
}

void Tnomem(void) {
  Tfailed("unable to malloc/realloc");
}

void Toutputerr(void) {
  Tfailed("write error on test harness output");
}

void Tensureoutputfile(void) {
  /* fixme: allow sending it elsewhere */
  Toutputfile= stdout;
}
