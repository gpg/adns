/*
 * addrfam.c
 * - address-family specific code
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

#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "internal.h"

/*
 * General address-family operations.
 */

#define SIN(sa) ((struct sockaddr_in *)(sa))
#define CSIN(sa) ((const struct sockaddr_in *)(sa))

#define SIN6(sa) ((struct sockaddr_in6 *)(sa))
#define CSIN6(sa) ((const struct sockaddr_in6 *)(sa))

/* This gadget (thanks, Richard Kettlewell) makes sure that we handle the
 * same set of address families in each switch. */
#define AF_CASES(pre)							\
  case AF_INET: goto pre##_inet;					\
  case AF_INET6: goto pre##_inet6

static void unknown_af(int af) {
  fprintf(stderr, "ADNS INTERNAL: unknown address family %d\n", af);
  abort();
}

#define IN6_ADDR_EQUALP(a, b)						\
  (!memcmp((a).s6_addr, (b).s6_addr, sizeof((a).s6_addr)))

int adns__genaddr_equal_p(int af, const union gen_addr *a,
			  int bf, const void *b) {
  const union gen_addr *bb= b;
  if (af != bf) return 0;
  switch (af) {
  AF_CASES(af);
  af_inet: return a->v4.s_addr == bb->v4.s_addr;
  af_inet6: return IN6_ADDR_EQUALP(a->v6, bb->v6);
  default: unknown_af(af); return -1;
  }
}

int adns__sockaddr_equal_p(const struct sockaddr *sa,
			   const struct sockaddr *sb) {
  if (sa->sa_family != sb->sa_family) return 0;
  switch (sa->sa_family) {
  AF_CASES(af);
  af_inet: {
    const struct sockaddr_in *sina= CSIN(sa), *sinb= CSIN(sb);
    return (sina->sin_addr.s_addr == sinb->sin_addr.s_addr &&
	    sina->sin_port == sinb->sin_port);
  }
  af_inet6: {
    /* Don't check the flowlabel.  That's apparently useful for routing
     * performance, but doesn't affect the address in any important
     * respect. */
    const struct sockaddr_in6 *sin6a= CSIN6(sa), *sin6b= CSIN6(sb);
    return (IN6_ADDR_EQUALP(sin6a->sin6_addr, sin6b->sin6_addr) &&
	    sin6a->sin6_port == sin6b->sin6_port &&
	    sin6a->sin6_scope_id == sin6b->sin6_scope_id);
  }
  default:
    unknown_af(sa->sa_family);
    return -1;
  }
}

int adns__addr_width(int af) {
  switch (af) {
  AF_CASES(af);
  af_inet: return 32;
  af_inet6: return 128;
  default: unknown_af(af); return -1;
  }
}

void adns__prefix_mask(int af, int len, union gen_addr *mask_r) {
  switch (af) {
  AF_CASES(af);
  af_inet:
    assert(len <= 32);
    mask_r->v4.s_addr= htonl(!len ? 0 : 0xffffffff << (32-len));
    break;
  af_inet6: {
    int i= len/8, j= len%8;
    unsigned char *m= mask_r->v6.s6_addr;
    assert(len <= 128);
    memset(m, 0xff, i);
    if (j) m[i++]= (0xff << (8-j)) & 0xff;
    memset(m+i, 0, 16-i);
  } break;
  default:
    unknown_af(af);
    break;
  }
}

int adns__guess_prefix_length(int af, const union gen_addr *addr) {
  switch (af) {
  AF_CASES(af);
  af_inet: {
    unsigned a= (ntohl(addr->v4.s_addr) >> 24) & 0xff;
    if (a < 128) return 8;
    else if (a < 192) return 16;
    else if (a < 224) return 24;
    else return -1;
  } break;
  af_inet6:
    return 64;
  default:
    unknown_af(af);
    return -1;
  }
}

int adns__addr_match_p(int addraf, const union gen_addr *addr,
		       int netaf, const union gen_addr *base,
		       const union gen_addr *mask)
{
  if (addraf != netaf) return 0;
  switch (addraf) {
  AF_CASES(af);
  af_inet:
    return (addr->v4.s_addr & mask->v4.s_addr) == base->v4.s_addr;
  af_inet6: {
    int i;
    const char *a= addr->v6.s6_addr;
    const char *b= base->v6.s6_addr;
    const char *m= mask->v6.s6_addr;
    for (i = 0; i < 16; i++)
      if ((a[i] & m[i]) != b[i]) return 0;
    return 1;
  } break;
  default:
    unknown_af(addraf);
    return -1;
  }
}

void adns__sockaddr_extract(const struct sockaddr *sa,
			    union gen_addr *a_r, int *port_r) {
  switch (sa->sa_family) {
  AF_CASES(af);
  af_inet: {
    const struct sockaddr_in *sin = CSIN(sa);
    if (port_r) *port_r= ntohs(sin->sin_port);
    if (a_r) a_r->v4= sin->sin_addr;
    break;
  }
  af_inet6: {
    const struct sockaddr_in6 *sin6 = CSIN6(sa);
    if (port_r) *port_r= ntohs(sin6->sin6_port);
    if (a_r) a_r->v6= sin6->sin6_addr;
    break;
  }
  default:
    unknown_af(sa->sa_family);
  }
}

void adns__sockaddr_inject(const union gen_addr *a, int port,
			   struct sockaddr *sa) {
  switch (sa->sa_family) {
  AF_CASES(af);
  af_inet: {
    struct sockaddr_in *sin = SIN(sa);
    if (port != -1) sin->sin_port= htons(port);
    if (a) sin->sin_addr= a->v4;
    break;
  }
  af_inet6: {
    struct sockaddr_in6 *sin6 = SIN6(sa);
    if (port != -1) sin6->sin6_port= htons(port);
    if (a) sin6->sin6_addr= a->v6;
    break;
  }
  default:
    unknown_af(sa->sa_family);
  }
}
