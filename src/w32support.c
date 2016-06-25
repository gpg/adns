/*
 * w32misc.c
 * - Helper functions for Windows.
 */
/*
 *  This file is
 *    Copyright (C) 2008 g10 Code GmbH
 *    Copyright (C) 2000, 2004 Jarle (jgaa) Aase <jgaa@jgaa.com>
 *    Copyright (C) 1995, 1996, 2001 Free Software Foundation, Inc.
 *
 *  It is part of adns, which is
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

#ifndef HAVE_W32_SYSTEM
#error This file is only used for Windows.
#endif

#include <stdlib.h>
#include <stdint.h>
#include <malloc.h>

#include "internal.h"

static int wsa_startup_failed;

/* Define missing error codes for older Windows compilers.  */
#ifndef ECONNREFUSED
#define ECONNREFUSED 107
#endif



int WINAPI
DllMain (HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
  if (reason == DLL_PROCESS_ATTACH)
    {
      static WSADATA wsdata;

      if (WSAStartup (0x0202, &wsdata))
        wsa_startup_failed = 1;
    }
  else if (reason == DLL_PROCESS_DETACH)
    {
      if (!wsa_startup_failed)
        WSACleanup ();
    }

  return TRUE;
}



/* Map a windows specific socket error code to an errno code.  */
int
adns__sock_wsa2errno (int err)
{
  switch (err)
    {
    case WSAENOTSOCK:
      return EINVAL;
    case WSAEWOULDBLOCK:
      return EAGAIN;
    case ERROR_BROKEN_PIPE:
      return EPIPE;
    case WSANOTINITIALISED:
      return ENOSYS;
    case WSAENOBUFS:
      return ENOBUFS;
    case WSAEMSGSIZE:
      return EMSGSIZE;
    case WSAECONNREFUSED:
      return ECONNREFUSED;
    default:
      return EIO;
    }
}


int
adns__sock_socket (int domain, int type, int proto)
{
  int fd;

  fd = socket (domain, type, proto);
  if (fd == -1)
    errno = adns__sock_wsa2errno (WSAGetLastError ());
  return fd;
}


int
adns__sock_connect (int fd, const struct sockaddr *addr, int addrlen)
{
  int res;

  res = connect (fd, addr, addrlen);
  if (res < 0)
    errno = adns__sock_wsa2errno (WSAGetLastError ());
  return res;
}


int
adns__sock_read (int fd, void *buffer, size_t size)
{
  int n;

  n = recv (fd, buffer, size, 0);
  if (n == -1)
    errno = adns__sock_wsa2errno (WSAGetLastError ());
  return n;
}


int
adns__sock_recvfrom(int fd, void *buffer, size_t size, int flags,
                    struct sockaddr *addr, int *addrlen)
{
  int n;

  n = recvfrom (fd, buffer, size, flags, addr, addrlen);
  if (n == -1)
    errno = adns__sock_wsa2errno (WSAGetLastError ());
  return n;
}


int
adns__sock_write (int fd, const void *buffer, size_t size)
{
  int n;

  n = send (fd, buffer, size, 0);
  if (n == -1)
    errno = adns__sock_wsa2errno (WSAGetLastError ());
  return n;
}


int
adns__sock_sendto (int fd, void *buffer, size_t size, int flags,
                   const struct sockaddr *addr, int length)
{
  int n;

  n = sendto (fd, buffer, size, flags, addr, length);
  if (n == -1)
    errno = adns__sock_wsa2errno (WSAGetLastError());
  return n;
}

/* writev implementation for use with sockets.  This should not be
   used for very large buffers, because we concatenate everything and
   use a single send.  It is sufficient for use in adns, though.

   [Taken and modified from the adns 1.0 W32 port.  Note that the
    original version never worked; that is adns via TCP did not worked
    with W32.].  */
int
adns__sock_writev (int fd, const struct iovec *iov, int iovcount)
{
  size_t total_len = 0;
  int rc, i;
  char *buf, *p;

  for (i=0; i < iovcount; i++)
    total_len += iov[i].iov_len;

  p = buf = alloca (total_len);
  for (i=0; i < iovcount; i++)
    {
      memcpy (p, iov[i].iov_base, iov[i].iov_len);
      p += iov[i].iov_len;
    }

  rc = send (fd, buf, total_len, 0);
  if (rc)
    errno = adns__sock_wsa2errno (WSAGetLastError());
  return rc;
}


int
adns__sock_close (int fd)
{
  int rc = closesocket(fd);
  if (rc)
    errno = adns__sock_wsa2errno (WSAGetLastError());
  return rc;
}


int
adns__sock_select (int nfds, fd_set *rset, fd_set *wset, fd_set *xset,
                   const struct timeval *timeout_arg)
{
  int rc;
  struct timeval timeout_buf, *timeout;

  if (timeout_arg)
    {
      timeout_buf = *timeout_arg;
      timeout = &timeout_buf;
    }
  else
    timeout = NULL;

  rc = select (nfds, rset, wset, xset, timeout);
  if (rc == -1)
    errno = adns__sock_wsa2errno (WSAGetLastError());
  return rc;
}


/* inet_aton implementation.  [Taken from the adns 1.0 W32 port.
   Copyright (C) 2000, 2004 Jarle (jgaa) Aase <jgaa@jgaa.com>]

   Returns true if the address is valid, false if not. */
int
adns__inet_aton (const char *cp, struct in_addr *inp)
{
  if (!cp || !*cp || !inp)
    {
      errno = EINVAL;
      return 0;
    }

  if (!strcmp(cp, "255.255.255.255"))
    {
      /*  Although this is a valid address, the old inet_addr function
          is not able to handle it.  */
        inp->s_addr = INADDR_NONE;
        return 1;
    }

  inp->s_addr = inet_addr (cp);
  return (inp->s_addr != INADDR_NONE);
}

