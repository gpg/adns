/*
 * hrecord.c
 * - complex test harness, recording routines
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

#include <assert.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "harness.h"

static int begin_set;
static struct timeval begin;

void Q_str(const char *str) {
  Tensureoutputfile();
  if (fprintf(Toutputfile," %s\n",str) == EOF) Toutputerr();
  if (fflush(Toutputfile)) Toutputerr();
}

void Q_vb(void) {
  if (!adns__vbuf_append(&vb,"",1)) Tnomem();
  Q_str(vb.buf);
}

static void Rvb(void) {
  Q_vb();
}
  
static void Rf(const char *fmt, ...) PRINTFFORMAT(1,2);
static void Rf(const char *fmt, ...) {
  va_list al;

  va_start(al,fmt);
  Tvbvf(fmt,al);
  va_end(al);
  Rvb();
}

static void Rerrno(const char *call) {
  int e;

  e= errno;
  Tvbf("%s ",call);
  Tvberrno(e);
  Rvb();
  errno= e;
}

int Hgettimeofday(struct timeval *tv, struct timezone *tz) {
  int r;
  struct timeval diff;

  assert(tv); assert(!tz);

  Qgettimeofday();

  r= gettimeofday(tv,0); if (r) Tfailed("gettimeofday");

  vb.used= 0;
  if (!begin_set) {
    Tvbf("gettimeofday= %ld.%06ld",tv->tv_sec,tv->tv_usec);
    begin= *tv;
    begin_set= 1;
  } else {
    diff.tv_sec= tv->tv_sec - begin.tv_sec;
    diff.tv_usec= tv->tv_usec - begin.tv_usec;
    if (diff.tv_usec < 0) {
      diff.tv_sec -= 1;
      diff.tv_usec += 1000000;
    }
    assert(diff.tv_sec >= 0);
    assert(diff.tv_usec >= 0);
    Tvbf("gettimeofday= +%ld.%06ld",diff.tv_sec,diff.tv_usec);
  }
  Rvb();
  
  return 0;
}

int Hselect(int n, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *to) {
  int r;
  
  Qselect(n,rfds,wfds,efds,to);

  r= select(n,rfds,wfds,efds,to);

  if (r==-1) {
    Rerrno("select");
  } else {
    vb.used= 0;
    Tvbf("select= %d",r);
    Tvbfdset(n,rfds);
    Tvbfdset(n,wfds);
    Tvbfdset(n,efds);
    Rvb();
  }

  if (to) memset(to,0x5a,sizeof(*to));

  return r;
}

int Hsocket(int domain, int type, int protocol) {
  int r;
  
  assert(domain == AF_INET);

  Qsocket(type);
  r= socket(domain,type,protocol); if (r==-1) Tfailed("socket");

  Rf("socket= %d",r);
  return r;
}

int Hfcntl(int fd, int cmd, ...) {
  long arg;
  int r;
  va_list al;

  if (cmd == F_SETFL) {
    va_start(al,cmd);
    arg= va_arg(al,long);
    va_end(al);
    Qfcntl_setfl(fd,cmd,arg);
    r= fcntl(fd, cmd, arg);
  } else {
    Qfcntl_other(fd,cmd);
    r= fcntl(fd, cmd);
  }

  if (r==-1) Tfailed("fcntl");
  Rf("fcntl= %d",r);
  return r;
}

int Hconnect(int fd, struct sockaddr *addr, int addrlen) {
  int r;
  
  Qconnect(fd,addr,addrlen);

  r= connect(fd, addr, addrlen);

  if (r) {
    Rerrno("connect");
  } else {
    Rf("connect= ok");
  }
  return r;
}

int Hclose(int fd) {
  Qclose(fd);
  return 0;
}

int Hsendto(int fd, const void *msg, int msglen, unsigned int flags,
	    const struct sockaddr *addr, int addrlen) {
  int r;
  
  assert(!flags);
  Qsendto(fd,msg,msglen,addr,addrlen);

  r= sendto(fd,msg,msglen,flags,addr,addrlen);
  if (r==-1) {
    Rerrno("sendto");
  } else {
    Rf("sendto= %d",r);
  }
  return r;
}

int Hrecvfrom(int fd, void *buf, int buflen, unsigned int flags,
	      struct sockaddr *addr, int *addrlen) {
  int r;
  
  assert(!flags);
  Qrecvfrom(fd,buflen,*addrlen);

  r= recvfrom(fd,buf,buflen,flags,addr,addrlen);
  if (r==-1) {
    Rerrno("recvfrom");
  } else {
    vb.used= 0;
    Tvbf("recvfrom= %d",r);
    Tvbaddr(addr,*addrlen);
    Tvbbytes(buf,r);
    Rvb();
  }

  return r;
}

int Hread(int fd, void *buf, size_t len) {
  int r;
  
  Qread(fd,len);

  r= read(fd,buf,len);
  if (r==-1) {
    Rerrno("read");
  } else {
    vb.used= 0;
    Tvba("read=");
    Tvbbytes(buf,r);
    Rvb();
  }

  return r;
}

int Hwrite(int fd, const void *buf, size_t len) {
  int r;
  
  Qwrite(fd,buf,len);

  r= write(fd,buf,len);
  if (r==-1) {
    Rerrno("write");
  } else {
    Rf("write= %d",r);
  }
  
  return r;
}
