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

#include "harness.h"
#include "internal.h"

static vbuf vb;

void Qgettimeofday(void) {
  Tsyscall("gettimeofday()");
}

void Qselect(int n, fd_set rfds, fd_set wfds, fd_set efds, const struct timeval *t) {
  char buf[100];

  sprintf(buf,"select(%d, [",n);
  vb.used= 0;
  Tvba(&vb,buf);
  Tvbfdset(&vb,n,rfds);
  Tvba(&vb,"], [");
  Tvbfdset(&vb,n,wfds);
  Tvba(&vb,"], [");
  Tvbfdset(&vb,n,efds);
  if (t) {
    sprintf(buf,"], %ld.%06ld)",t->tv_sec,t->tv_usec);
    Tvba(&vb,buf);
  } else {
    Tvba(&vb,"], NULL)");
  }
  Tvbfin();
  Tsyscall(vb.buf);
}

void Qsocket(int type) {
  switch (type) {
  case SOCK_STREAM: Tsyscall("socket(,SOCK_STREAM,)"); break;
  case SOCK_DGRAM:  Tsyscall("socket(,SOCK_DGRAM,)");  break;
  default: abort();
  }
}

void Qfcntl(int fd, int cmd, long arg) {
  static char buf[100];

  switch (cmd) {
  case F_GETFL:
  sprintf(buf,"fcntl(%d, %s, %ld)",
}

void Qconnect(int fd, struct sockaddr *addr, int addrlen);
void Qclose(int fd);

void Qsendto(int fd, const void *msg, int msglen, unsigned int flags,
	     const struct sockaddr *addr, int addrlen);
void Qrecvfrom(int fd, int buflen, unsigned int flags, int *addrlen);

void Qread(int fd, size_t len);
void Qwrite(int fd, const void *buf, size_t len);
