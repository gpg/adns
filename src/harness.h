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
#include <unistd.h>

/* We override several system calls with #define's */

int Hgettimeofday(struct timeval *tv, struct timezone *tz);
int Hselect(int n, fd_set reads, fd_set writes, fd_set excepts, struct timeval *to);

int Hsocket(int domain, int type, int protocol);
int Hfcntl(int fd, int cmd, long arg);
int Hconnect(int fd, struct sockaddr *addr, int addrlen);
int Hclose(int fd);

int Hsendto(int fd, const void *msg, int msglen, unsigned int flags,
	    const struct sockaddr *addr, int addrlen);
int Hrecvfrom(int fd, void *buf, int buflen, unsigned int flags,
	      struct sockaddr *addr, int *addrlen);

int Hread(int fd, void *buf, size_t len);
int Hwrite(int fd, const void *buf, size_t len);

/* There is a Q function (Q for Question) for each such syscall;
 * it constructs a string representing the call, and
 * calls Tsyscall() on it.
 */

void Tsyscall(const char *string);

void Qgettimeofday(void);
void Qselect(int n, fd_set rfds, fd_set wfds, fd_set efds, const struct timeval *t);

void Qsocket(int type);
void Qfcntl(int fd, int cmd, long arg);
void Qconnect(int fd, struct sockaddr *addr, int addrlen);
void Qclose(int fd);

void Qsendto(int fd, const void *msg, int msglen, unsigned int flags,
	     const struct sockaddr *addr, int addrlen);
void Qrecvfrom(int fd, int buflen, unsigned int flags, int *addrlen);

void Qread(int fd, size_t len);
void Qwrite(int fd, const void *buf, size_t len);

#endif
