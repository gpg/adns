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

#include "harness.h"

static int begin_set;
static struct timeval begin;

int Hgettimeofday(struct timeval *tv, struct timezone *tz) {
  int r;
  struct timeval diff;

  assert(tv); assert(!tz);

  Qgettimeofday();

  r= gettimeofday(tv,0); if (r) Tfailed("gettimeofday");

  if (!begin_set) {
    printf(" gettimeofday= %ld.%06ld",tv->tv_sec,tv->tv_usec);
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
    Tprintf(" gettimeofday= +%ld.%06ld\n",diff.tv_sec,diff.tv_usec);
  }
  return 0;
}

int Hselect(int n, fd_set reads, fd_set writes, fd_set excepts, struct timeval *to) {
  Qselect(n,reads,writes,excepts,to);

  r= select(n,reads,writes,excepts,to);

  if (r==-1) {
    Terrorno("select");
  } else {
    Tprintf(" select= %d",r);
    Tfdset(reads); Tfdset(writes); Tfdset(excepts);
    Tprintf("\n");
  }

  if (to) memset(to,0x5a,sizeof(*to));
}

int Hsocket(int domain, int type, int protocol) {
  assert(domain == AF_INET);

  Qsocket(type);
  r= socket(domain,type,protocol); if (r) Tfailed("socket");

  Tprintf(" socket= %d\n",r);
  return r;
}

int Hfcntl(int fd, int cmd, long arg) {
  Qfcntl(fd,cmd,arg);

  r= fcntl(fd, cmd, arg); if (r==-1) Tfailed("fcntl");

  Tprintf(" fcntl= %d\n",r);
  return r;
}

int Hconnect(int fd, struct sockaddr *addr, int addrlen) {
  Qconnect(fd,addr,addrlen);

  r= connect(fd, addr, addrlen);

  if (r) {
    Terrno("connect");
  } else {
    Tprintf(" connect= OK\n");
  }
  return r;
}

int Hclose(int fd) {
  Qclose(fd);
  return 0;
}

int Hsendto(int fd, const void *msg, int msglen, unsigned int flags,
	    const struct sockaddr *addr, int addrlen) {
  assert(!flags)
  Qsendto(fd,msg,msglen,addr,addrlen);

  r= sendto(fd,msg,msglen,flags,addr,addrlen);
  if (r==-1) {
    Terrno("sendto");
  } else {
    Tprintf(" sendto= %d\n",r);
  }
  return r;
}

int Hrecvfrom(int fd, void *buf, int buflen, unsigned int flags,
	      struct sockaddr *addr, int *addrlen) {
  assert(!flags)
  Qrecvfrom(fd,buflen,addr,*addrlen);

  r= recvfrom(fd,buf,buflen,flags,addr,addrlen);
  if (r==-1) {
    Terrno("recvfrom");
  } else {
    Tprintf(" recvfrom=",r);
    Taddr(addr,addrlen);
    Tbuf(buf,r);
    Tprintf("\n");
  }

  return r;
}

int Hread(int fd, void *buf, size_t len) {
  Qread(fd,len);

  r= read(fd,buf,len);
  if (r==-1) {
    Terrno("read");
  } else {
    Tprintf(" read=");
    Tbuf(buf,r);
    Tprintf("\n");
  }

  return r;
}

int Hwrite(int fd, const void *buf, size_t len) {
  Qwrite(fd,buf,len);

  r= write(fd,buf,len);
  if (r==-1) {
    Terrno("write");
  } else {
    Tprintf(" write= %d\n",r);
  }
  
  return r;
}
