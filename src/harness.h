/*
 * harness.h
 * - complex test harness function declarations, not part of the library
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

#ifndef HARNESS_H_INCLUDED
#define HARNESS_H_INCLUDED

#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>

#include "internal.h"

/* We override several system calls with #define's */

int Hgettimeofday(struct timeval *tv, struct timezone *tz);
int Hselect(int n, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *to);

int Hsocket(int domain, int type, int protocol);
int Hfcntl(int fd, int cmd, ...);
int Hconnect(int fd, struct sockaddr *addr, int addrlen);
int Hclose(int fd);

int Hsendto(int fd, const void *msg, int msglen, unsigned int flags,
	    const struct sockaddr *addr, int addrlen);
int Hrecvfrom(int fd, void *buf, int buflen, unsigned int flags,
	      struct sockaddr *addr, int *addrlen);

int Hread(int fd, void *buf, size_t len);
int Hwrite(int fd, const void *buf, size_t len);

/* There is a Q function (Q for Question) for each such syscall;
 * it constructs a string representing the call, and calls Q_str
 * on it, or constructs it in vb and calls Q_vb;
 */

void Qgettimeofday(void);
void Qselect(int n, const fd_set *rfds, const fd_set *wfds, const fd_set *efds,
	     const struct timeval *to);

void Qsocket(int type);
void Qfcntl_setfl(int fd, int cmd, long arg);
void Qfcntl_other(int fd, int cmd);
void Qconnect(int fd, struct sockaddr *addr, int addrlen);
void Qclose(int fd);

void Qsendto(int fd, const void *msg, int msglen,
	     const struct sockaddr *addr, int addrlen);
void Qrecvfrom(int fd, int buflen, int addrlen);

void Qread(int fd, size_t len);
void Qwrite(int fd, const void *buf, size_t len);

void Q_str(const char *str);
void Q_vb(void);

/* General help functions */

void Tfailed(const char *why);
void Toutputerr(void);
void Tnomem(void);
void Tfsyscallr(const char *fmt, ...) PRINTFFORMAT(1,2);
void Tensureoutputfile(void);

void Tvbf(const char *fmt, ...) PRINTFFORMAT(1,2);
void Tvbvf(const char *fmt, va_list al);
void Tvbfdset(int max, const fd_set *set);
void Tvbaddr(const struct sockaddr *addr, int addrlen);
void Tvbbytes(const void *buf, int len);
void Tvberrno(int e);
void Tvba(const char *str);

/* Shared globals */

extern vbuf vb;
extern FILE *Toutputfile;

extern const struct Terrno { const char *n; int v; } Terrnos[];
  
#endif
