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
#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

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

static void unknown_af(int af) NONRETURNING;
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

/*
 * addr2text and text2addr
 */

#define ADDRFAM_DEBUG
#ifdef ADDRFAM_DEBUG
static void af_debug_func(const char *fmt, ...) {
  int esave= errno;
  va_list al;
  va_start(al,fmt);
  vfprintf(stderr,fmt,al);
  va_end(al);
  errno= esave;
}
# define af_debug(fmt,...) \
  (af_debug_func("%s: " fmt "\n", __func__, __VA_ARGS__))
#else
# define af_debug(fmt,...) ((void)("" fmt "", __VA_ARGS__))
#endif

static bool addrtext_our_errno(int e) {
  return
    e==EAFNOSUPPORT ||
    e==EINVAL ||
    e==ENOSPC ||
    e==ENOSYS;
}

static bool addrtext_scope_use_ifname(const struct sockaddr *sa) {
  const struct in6_addr *in6= &CSIN6(sa)->sin6_addr;
  return
    IN6_IS_ADDR_LINKLOCAL(in6) ||
    IN6_IS_ADDR_MC_LINKLOCAL(in6);
}

int adns_text2addr(const char *text, uint16_t port, adns_queryflags flags,
		   struct sockaddr *sa, socklen_t *salen_io) {
  int af;
  char copybuf[INET6_ADDRSTRLEN];
  const char *parse=text;
  const char *scopestr=0;
  socklen_t needlen;
  void *dst;
  uint16_t *portp;

#define INVAL(how) do{				\
  af_debug("invalid: %s: `%s'", how, text);	\
  return EINVAL;				\
}while(0)

#define AFCORE(INETx,SINx,sinx)			\
    af= AF_##INETx;				\
    dst = &SINx(sa)->sinx##_addr;		\
    portp = &SINx(sa)->sinx##_port;		\
    needlen= sizeof(*SINx(sa));

  if (!strchr(text, ':')) { /* INET */

    AFCORE(INET,SIN,sin);

  } else { /* INET6 */

    AFCORE(INET6,SIN6,sin6);

    const char *percent= strchr(text, '%');
    if (percent) {
      ptrdiff_t lhslen = percent - text;
      if (lhslen >= INET6_ADDRSTRLEN) INVAL("scoped addr lhs too long");
      memcpy(copybuf, text, lhslen);
      copybuf[lhslen]= 0;

      parse= copybuf;
      scopestr= percent+1;

      af_debug("will parse scoped addr `%s' %% `%s'", parse, scopestr);
    }

  }

#undef AFCORE

  if (scopestr && (flags & adns_qf_addrlit_scope_forbid))
    INVAL("scoped addr but _scope_forbid");

  if (*salen_io < needlen) {
    *salen_io = needlen;
    return ENOSPC;
  }

  memset(sa, 0, needlen);

  sa->sa_family= af;
  *portp = htons(port);

  if (af == AF_INET && !(flags & adns_qf_addrlit_ipv4_quadonly)) {
    /* we have to use inet_aton to deal with non-dotted-quad literals */
    int r= inet_aton(parse,&SIN(sa)->sin_addr);
    if (!r) INVAL("inet_aton rejected");
  } else {
    int r= inet_pton(af,parse,dst);
    if (!r) INVAL("inet_pton rejected");
    assert(r>0);
  }

  if (scopestr) {
    errno=0;
    char *ep;
    unsigned long scope= strtoul(scopestr,&ep,10);
    if (errno==ERANGE) INVAL("numeric scope id too large for unsigned long");
    assert(!errno);
    if (!*ep) {
      if (scope > ~(uint32_t)0)
	INVAL("numeric scope id too large for uint32_t");
    } else { /* !!*ep */
      if (flags & adns_qf_addrlit_scope_numeric)
	INVAL("non-numeric scope but _scope_numeric");
      if (!addrtext_scope_use_ifname(sa)) {
	af_debug("cannot convert non-numeric scope"
		 " in non-link-local addr `%s'", text);
	return ENOSYS;
      }
      errno= 0;
      scope= if_nametoindex(scopestr);
      if (!scope) {
	/* RFC3493 says "No errors are defined".  It's not clear
	 * whether that is supposed to mean if_nametoindex "can't
	 * fail" (other than by the supplied name not being that of an
	 * interface) which seems unrealistic, or that it conflates
	 * all its errors together by failing to set errno, or simply
	 * that they didn't bother to document the errors.
	 *
	 * glibc, FreeBSD and OpenBSD all set errno (to ENXIO when
	 * appropriate).  See Debian bug #749349.
	 *
	 * We attempt to deal with this by clearing errno to start
	 * with, and then perhaps mapping the results. */
	af_debug("if_nametoindex rejected scope name (errno=%s)",
		 strerror(errno));
	if (errno==0) {
	  return ENXIO;
	} else if (addrtext_our_errno(errno)) {
	  /* we use these for other purposes, urgh. */
	  perror("adns: adns_text2addr: if_nametoindex"
		 " failed with unexpected error");
	  return EIO;
	} else {
	  return errno;
	}
      } else { /* ix>0 */
	if (scope > ~(uint32_t)0) {
	  fprintf(stderr,"adns: adns_text2addr: if_nametoindex"
		  " returned an interface index >=2^32 which will not fit"
		  " in sockaddr_in6.sin6_scope_id");
	  return EIO;
	}
      }
    } /* else; !!*ep */

    SIN6(sa)->sin6_scope_id= scope;
  } /* if (scopestr) */

  *salen_io = needlen;
  return 0;
}

int adns_addr2text(const struct sockaddr *sa, adns_queryflags flags,
		   char *buffer, int *buflen_io, int *port_r) {
  const void *src;
  int port;

  if (*buflen_io < ADNS_ADDR2TEXT_BUFLEN) {
    *buflen_io = ADNS_ADDR2TEXT_BUFLEN;
    return ENOSPC;
  }

  switch (sa->sa_family) {
    AF_CASES(af);
    af_inet:  src= &CSIN(sa)->sin_addr;    port= CSIN(sa)->sin_port;    break;
    af_inet6: src= &CSIN6(sa)->sin6_addr;  port= CSIN6(sa)->sin6_port;  break;
    default: return EAFNOSUPPORT;
  }

  const char *ok= inet_ntop(sa->sa_family, src, buffer, *buflen_io);
  assert(ok);

  if (sa->sa_family == AF_INET6) {
    uint32_t scope = CSIN6(sa)->sin6_scope_id;
    if (scope) {
      if (flags & adns_qf_addrlit_scope_forbid)
	return EINVAL;
      int scopeoffset = strlen(buffer);
      int remain = *buflen_io - scopeoffset;
      char *scopeptr =  buffer + scopeoffset;
      assert(remain >= IF_NAMESIZE+1/*%*/);
      *scopeptr++= '%'; remain--;
      bool parsedname = 0;
      af_debug("will print scoped addr `%.*s' %% %"PRIu32"",
	       scopeoffset,buffer, scope);
      if (scope <= UINT_MAX /* so we can pass it to if_indextoname */
	  && !(flags & adns_qf_addrlit_scope_numeric)
	  && addrtext_scope_use_ifname(sa)) {
	parsedname = if_indextoname(scope, scopeptr);
	if (!parsedname) {
	  af_debug("if_indextoname rejected scope (errno=%s)",
		   strerror(errno));
	  if (errno==ENXIO) {
	    /* fair enough, show it as a number then */
	  } else if (addrtext_our_errno(errno)) {
	    /* we use these for other purposes, urgh. */
	    perror("adns: adns_addr2text: if_indextoname"
		   " failed with unexpected error");
	    return EIO;
	  } else {
	    return errno;
	  }
	}
      }
      if (!parsedname) {
	int r = snprintf(scopeptr, remain,
			 "%"PRIu32"", scope);
	assert(r < *buflen_io - scopeoffset);
      }
      af_debug("printed scoped addr `%s'", buffer);
    }
  }

  if (port_r) *port_r= ntohs(port);
  return 0;
}

char *adns__sockaddr_ntoa(const struct sockaddr *sa, char *buf) {
  int err;
  int len= ADNS_ADDR2TEXT_BUFLEN;

  err= adns_addr2text(sa, 0, buf, &len, 0);
  if (err == EIO)
    err= adns_addr2text(sa, adns_qf_addrlit_scope_numeric, buf, &len, 0);
  assert(!err);
  return buf;
}

/*
 * Reverse-domain parsing and construction.
 */

int adns__make_reverse_domain(const struct sockaddr *sa, const char *zone,
			      char **buf_io, size_t bufsz,
			      char **buf_free_r) {
  size_t req;
  char *p;
  unsigned c, y;
  unsigned long aa;
  const unsigned char *ap;
  int i, j;

  switch (sa->sa_family) {
  AF_CASES(af);
  af_inet:
    req= 4 * 4;
    if (!zone) zone= "in-addr.arpa";
    break;
  af_inet6:
    req = 2 * 32;
    if (!zone) zone= "ip6.arpa";
    break;
  default:
    return ENOSYS;
  }

  req += strlen(zone) + 1;
  if (req <= bufsz)
    p= *buf_io;
  else {
    p= malloc(req); if (!p) return errno;
    *buf_free_r = p;
  }

  *buf_io= p;
  switch (sa->sa_family) {
  AF_CASES(bf);
  bf_inet:
    aa= ntohl(CSIN(sa)->sin_addr.s_addr);
    for (i=0; i<4; i++) {
      p += sprintf(p, "%d", (int)(aa & 0xff));
      *p++= '.';
      aa >>= 8;
    }
    break;
  bf_inet6:
    ap= CSIN6(sa)->sin6_addr.s6_addr + 16;
    for (i=0; i<16; i++) {
      c= *--ap;
      for (j=0; j<2; j++) {
	y= c & 0xf;
	*p++= (y < 10) ? y + '0' : y - 10 + 'a';
	c >>= 4;
	*p++= '.';
      }
    }
    break;
  default:
    unknown_af(sa->sa_family);
  }

  strcpy(p, zone);
  return 0;
}


static int inet_rev_parsecomp(const char *p, size_t n) {
  int i= 0;
  if (n > 3) return -1;

  while (n--) {
    if ('0' <= *p && *p <= '9') i= 10*i + *p++ - '0';
    else return -1;
  }
  return i;
}

static void inet_rev_mkaddr(union gen_addr *addr, const byte *ipv) {
  addr->v4.s_addr= htonl((ipv[3]<<24) | (ipv[2]<<16) |
			 (ipv[1]<<8) | (ipv[0]));
}

static int inet6_rev_parsecomp(const char *p, size_t n) {
  if (n != 1) return -1;
  else if ('0' <= *p && *p <= '9') return *p - '0';
  else if ('a' <= *p && *p <= 'f') return *p - 'a' + 10;
  else if ('A' <= *p && *p <= 'F') return *p - 'a' + 10;
  else return -1;
}

static void inet6_rev_mkaddr(union gen_addr *addr, const byte *ipv) {
  unsigned char *a= addr->v6.s6_addr;
  int i;

  for (i=0; i<16; i++)
    a[i]= (ipv[31-2*i] << 4) | (ipv[30-2*i] << 0);
}

static const struct revparse_domain {
  int af;				/* address family */
  int nrevlab;				/* n of reverse-address labels */
  adns_rrtype rrtype;			/* forward-lookup type */

  int (*rev_parsecomp)(const char *p, size_t n);
  /* parse a single component from a label; return the integer value, or -1
   * if it was unintelligible.
   */

  void (*rev_mkaddr)(union gen_addr *addr, const byte *ipv);
  /* write out the parsed address from a vector of parsed components */

  const char *const tail[3];		/* tail label names */
} revparse_domains[NREVDOMAINS] = {
  { AF_INET, 4, adns_r_a, inet_rev_parsecomp, inet_rev_mkaddr,
    { DNS_INADDR_ARPA, 0 } },
  { AF_INET6, 32, adns_r_aaaa, inet6_rev_parsecomp, inet6_rev_mkaddr,
    { DNS_IP6_ARPA, 0 } },
};

#define REVDOMAIN_MAP(rps, labnum)					\
  ((labnum) ? (rps)->map : (1 << NREVDOMAINS) - 1)

int adns__revparse_label(struct revparse_state *rps, int labnum,
			 const char *label, int lablen) {
  unsigned f= REVDOMAIN_MAP(rps, labnum);
  const struct revparse_domain *rpd;
  const char *tp;
  unsigned d;
  int i, ac;

  for (rpd=revparse_domains, i=0, d=1; i<NREVDOMAINS; rpd++, i++, d <<= 1) {
    if (!(f & d)) continue;
    if (labnum >= rpd->nrevlab) {
      tp = rpd->tail[labnum - rpd->nrevlab];
      if (!tp || strncmp(label, tp, lablen) != 0 || tp[lablen])
	goto mismatch;
    } else {
      ac= rpd->rev_parsecomp(label, lablen);
      if (ac < 0) goto mismatch;
      assert(labnum < sizeof(rps->ipv[i]));
      rps->ipv[i][labnum]= ac;
    }
    continue;

  mismatch:
    f &= ~d;
    if (!f) return -1;
  }

  rps->map= f;
  return 0;
}

int adns__revparse_done(struct revparse_state *rps, int nlabels,
			adns_rrtype *rrtype_r, struct af_addr *addr_r) {
  unsigned f= REVDOMAIN_MAP(rps, nlabels);
  const struct revparse_domain *rpd;
  unsigned d;
  int i, found= -1;

  for (rpd=revparse_domains, i=0, d=1; i<NREVDOMAINS; rpd++, i++, d <<= 1) {
    if (!(f & d)) continue;
    if (nlabels >= rpd->nrevlab && !rpd->tail[nlabels - rpd->nrevlab])
      { found = i; continue; }
    f &= ~d;
    if (!f) return -1;
  }
  assert(found >= 0); assert(f == (1 << found));

  rpd= &revparse_domains[found];
  *rrtype_r= rpd->rrtype;
  addr_r->af= rpd->af;
  rpd->rev_mkaddr(&addr_r->addr, rps->ipv[found]);
  return 0;
}
