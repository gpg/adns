/*
 * platform.h
 * - platform specific declarations
 */
/*
 *  This file is part of adns, which is
 *    Copyright (C) 1997-2000,2003,2006  Ian Jackson
 *    Copyright (C) 1999-2000,2003,2006  Tony Finch
 *    Copyright (C) 1991 Massachusetts Institute of Technology
 *  (See the file INSTALL for full details.)
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

#ifndef ADNS_PLATFORM_H_INCLUDED
#define ADNS_PLATFORM_H_INCLUDED

#ifdef HAVE_W32_SYSTEM
/*
    W32 API platform (Windows)
 */
# define WIN32_LEAN_AND_MEAN 
# include <windows.h>

/* Missing errorcodes.  See also adns__sock_wsa2errno.  */
# ifndef ENOBUFS
#  define ENOBUFS WSAENOBUFS
# endif
# ifndef EWOULDBLOCK
#  define EWOULDBLOCK EAGAIN
# endif
# ifndef EINPROGRESS
         /* Although mapping EWOULDBLOCK to EAGAIN is not correct, it
            is sufficient for us. */ 
#  define EINPROGRESS EAGAIN  
# endif
# ifndef ENOPROTOOPT
#  define ENOPROTOOPT EINVAL
# endif
# ifndef EMSGSIZE
#  define EMSGSIZE WSAEMSGSIZE
# endif


/* We need this for writev in w32misc.c.  */
struct iovec 
{
  char *iov_base;
  int   iov_len; 
};


/* w32support.c:  */
int adns__sock_wsa2errno (int err);

int adns__sock_socket (int domain, int type, int proto);
int adns__sock_connect (int fd, const struct sockaddr *addr, int addrlen);
int adns__sock_read (int fd, void *buffer, size_t size);
int adns__sock_recvfrom(int fd, void *buffer, size_t size, int flags,
                        struct sockaddr *addr, int *addrlen);
int adns__sock_write (int fd, const void *buffer, size_t size);
int adns__sock_sendto (int fd, void *buffer, size_t size, int flags, 
                       const struct sockaddr *addr, int length);
int adns__sock_writev (int fd, const struct iovec *iov, int iovcount);
int adns__sock_close (int fd);
int adns__sock_select (int nfds, fd_set *rset, fd_set *wset, fd_set *xset,
                       const struct timeval *timeout);
int adns__inet_aton (const char *cp, struct in_addr *inp);


/* w32extra.c:  */
#ifndef HAVE_GETTIMEOFDAY
int gettimeofday (struct timeval *__restrict__ tp, void *__restrict__ tzp);
#endif
long int nrand48 (unsigned short int xsubi[3]);

#else 
/*
    Generic POSIX platform. 
 */


#define adns__sock_socket(a,b,c)         socket((a),(b),(c))
#define adns__sock_connect(a,b,c)        connect((a),(b),(c))
#define adns__sock_read(a,b,c)           read((a),(b),(c))
#define adns__sock_recvfrom(a,b,c,d,e,f) recvfrom((a),(b),(c),(d),(e),(f))
#define adns__sock_write(a,b,c)          write((a),(b),(c))
#define adns__sock_sendto(a,b,c,d,e,f)   sendto((a),(b),(c),(d),(e),(f))
#define adns__sock_writev(a, b, c)       writev((a),(b),(c)) 
#define adns__sock_close(a)              close((a))
#define adns__sock_select(a,b,c,d,e)     select((a),(b),(c),(d),(e))
#define adns__inet_aton(a,b)             inet_aton((a),(b))


#endif


#endif /*ADNS_PLATFORM_H_INCLUDED*/
