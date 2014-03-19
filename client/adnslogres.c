/*
 * adnslogres.c
 * - a replacement for the Apache logresolve program using adns
 */
/*
 *  This file is
 *   Copyright (C) 1999-2000 Tony Finch <dot@dotat.at>
 *   Copyright (C) 1999-2000 Ian Jackson <ian@davenant.greenend.org.uk>
 *   Copyright (C) 1998, 1999, 2000, 2001, 2008 Free Software Foundation, Inc.
 *
 *  It is part of adns, which is
 *    Copyright (C) 1997-2000,2003,2006  Ian Jackson
 *    Copyright (C) 1999-2000,2003,2006  Tony Finch
 *    Copyright (C) 1991 Massachusetts Institute of Technology
 *  (See the file INSTALL for full details.)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *  This version was originally supplied by Tony Finch, but has been
 *  modified by Ian Jackson as it was incorporated into adns and
 *  subsequently.
 */

#include <sys/types.h>
#include <sys/time.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <assert.h>

#include "config.h"
#include "adns.h"
#include "client.h"


#ifdef ADNS_REGRESS_TEST
# include "hredirect.h"
#endif

/* maximum number of concurrent DNS queries */
#define MAXMAXPENDING 64000
#define DEFMAXPENDING 2000

/* maximum length of a line */
#define MAXLINE 2048

/* Length of a buffer to hold an expanded IP addr string incl 0.  */
#define FULLIPBUFLEN 33

/* option flags */
#define OPT_DEBUG 1
#define OPT_POLL 2
#define OPT_PRIVACY 4
#define OPT_VHOST 8

static const char *const progname= "adnslogres";
static const char *config_text;
static const char *salt;

#define guard_null(str) ((str) ? (str) : "")

#define sensible_ctype(type,ch) (type((unsigned char)(ch)))
  /* isfoo() functions from ctype.h can't safely be fed char - blech ! */

static void msg(const char *fmt, ...) {
  va_list al;

  fprintf(stderr, "%s: ", progname);
  va_start(al,fmt);
  vfprintf(stderr, fmt, al);
  va_end(al);
  fputc('\n',stderr);
}

static void aargh(const char *cause) {
  const char *why = strerror(errno);
  if (!why) why = "Unknown error";
  msg("%s: %s (%d)", cause, why, errno);
  exit(1);
}





/*
 * Rotate the 32 bit integer X by N bytes.
 */
#if defined(__GNUC__) && defined(__i386__)
static inline uint32_t
rol (uint32_t x, int n)
{
  __asm__("roll %%cl,%0"
          :"=r" (x)
          :"0" (x),"c" (n));
  return x;
}
#else
#define rol(x,n) ( ((x) << (n)) | ((x) >> (32-(n))) )
#endif

/* Structure holding the context for the RIPE-MD160 computation.  */
typedef struct
{
  uint32_t h0, h1, h2, h3, h4;
  uint32_t nblocks;
  unsigned char buf[64];
  int  count;
} rmd160_context_t;



static void
rmd160_init (rmd160_context_t *hd)
{
  hd->h0 = 0x67452301;
  hd->h1 = 0xEFCDAB89;
  hd->h2 = 0x98BADCFE;
  hd->h3 = 0x10325476;
  hd->h4 = 0xC3D2E1F0;
  hd->nblocks = 0;
  hd->count = 0;
}



/*
 * Transform the message X which consists of 16 32-bit-words.
 */
static void
transform (rmd160_context_t *hd, const unsigned char *data)
{
  uint32_t a,b,c,d,e,aa,bb,cc,dd,ee,t;
#ifdef BIG_ENDIAN_HOST
  uint32_t x[16];
  {
    int i;
    unsigned char *p2, *p1;
    for (i=0, p1=data, p2=(unsigned char*)x; i < 16; i++, p2 += 4 )
      {
        p2[3] = *p1++;
        p2[2] = *p1++;
        p2[1] = *p1++;
	p2[0] = *p1++;
      }
  }
#else
  uint32_t x[16];
  memcpy (x, data, 64);
#endif


#define K0  0x00000000
#define K1  0x5A827999
#define K2  0x6ED9EBA1
#define K3  0x8F1BBCDC
#define K4  0xA953FD4E
#define KK0 0x50A28BE6
#define KK1 0x5C4DD124
#define KK2 0x6D703EF3
#define KK3 0x7A6D76E9
#define KK4 0x00000000
#define F0(x,y,z)   ( (x) ^ (y) ^ (z) )
#define F1(x,y,z)   ( ((x) & (y)) | (~(x) & (z)) )
#define F2(x,y,z)   ( ((x) | ~(y)) ^ (z) )
#define F3(x,y,z)   ( ((x) & (z)) | ((y) & ~(z)) )
#define F4(x,y,z)   ( (x) ^ ((y) | ~(z)) )
#define R(a,b,c,d,e,f,k,r,s) do { t = a + f(b,c,d) + k + x[r]; \
				  a = rol(t,s) + e;	       \
				  c = rol(c,10);	       \
				} while(0)

  /* Left lane.  */
  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  R( a, b, c, d, e, F0, K0,  0, 11 );
  R( e, a, b, c, d, F0, K0,  1, 14 );
  R( d, e, a, b, c, F0, K0,  2, 15 );
  R( c, d, e, a, b, F0, K0,  3, 12 );
  R( b, c, d, e, a, F0, K0,  4,  5 );
  R( a, b, c, d, e, F0, K0,  5,  8 );
  R( e, a, b, c, d, F0, K0,  6,  7 );
  R( d, e, a, b, c, F0, K0,  7,  9 );
  R( c, d, e, a, b, F0, K0,  8, 11 );
  R( b, c, d, e, a, F0, K0,  9, 13 );
  R( a, b, c, d, e, F0, K0, 10, 14 );
  R( e, a, b, c, d, F0, K0, 11, 15 );
  R( d, e, a, b, c, F0, K0, 12,  6 );
  R( c, d, e, a, b, F0, K0, 13,  7 );
  R( b, c, d, e, a, F0, K0, 14,  9 );
  R( a, b, c, d, e, F0, K0, 15,  8 );
  R( e, a, b, c, d, F1, K1,  7,  7 );
  R( d, e, a, b, c, F1, K1,  4,  6 );
  R( c, d, e, a, b, F1, K1, 13,  8 );
  R( b, c, d, e, a, F1, K1,  1, 13 );
  R( a, b, c, d, e, F1, K1, 10, 11 );
  R( e, a, b, c, d, F1, K1,  6,  9 );
  R( d, e, a, b, c, F1, K1, 15,  7 );
  R( c, d, e, a, b, F1, K1,  3, 15 );
  R( b, c, d, e, a, F1, K1, 12,  7 );
  R( a, b, c, d, e, F1, K1,  0, 12 );
  R( e, a, b, c, d, F1, K1,  9, 15 );
  R( d, e, a, b, c, F1, K1,  5,  9 );
  R( c, d, e, a, b, F1, K1,  2, 11 );
  R( b, c, d, e, a, F1, K1, 14,  7 );
  R( a, b, c, d, e, F1, K1, 11, 13 );
  R( e, a, b, c, d, F1, K1,  8, 12 );
  R( d, e, a, b, c, F2, K2,  3, 11 );
  R( c, d, e, a, b, F2, K2, 10, 13 );
  R( b, c, d, e, a, F2, K2, 14,  6 );
  R( a, b, c, d, e, F2, K2,  4,  7 );
  R( e, a, b, c, d, F2, K2,  9, 14 );
  R( d, e, a, b, c, F2, K2, 15,  9 );
  R( c, d, e, a, b, F2, K2,  8, 13 );
  R( b, c, d, e, a, F2, K2,  1, 15 );
  R( a, b, c, d, e, F2, K2,  2, 14 );
  R( e, a, b, c, d, F2, K2,  7,  8 );
  R( d, e, a, b, c, F2, K2,  0, 13 );
  R( c, d, e, a, b, F2, K2,  6,  6 );
  R( b, c, d, e, a, F2, K2, 13,  5 );
  R( a, b, c, d, e, F2, K2, 11, 12 );
  R( e, a, b, c, d, F2, K2,  5,  7 );
  R( d, e, a, b, c, F2, K2, 12,  5 );
  R( c, d, e, a, b, F3, K3,  1, 11 );
  R( b, c, d, e, a, F3, K3,  9, 12 );
  R( a, b, c, d, e, F3, K3, 11, 14 );
  R( e, a, b, c, d, F3, K3, 10, 15 );
  R( d, e, a, b, c, F3, K3,  0, 14 );
  R( c, d, e, a, b, F3, K3,  8, 15 );
  R( b, c, d, e, a, F3, K3, 12,  9 );
  R( a, b, c, d, e, F3, K3,  4,  8 );
  R( e, a, b, c, d, F3, K3, 13,  9 );
  R( d, e, a, b, c, F3, K3,  3, 14 );
  R( c, d, e, a, b, F3, K3,  7,  5 );
  R( b, c, d, e, a, F3, K3, 15,  6 );
  R( a, b, c, d, e, F3, K3, 14,  8 );
  R( e, a, b, c, d, F3, K3,  5,  6 );
  R( d, e, a, b, c, F3, K3,  6,  5 );
  R( c, d, e, a, b, F3, K3,  2, 12 );
  R( b, c, d, e, a, F4, K4,  4,  9 );
  R( a, b, c, d, e, F4, K4,  0, 15 );
  R( e, a, b, c, d, F4, K4,  5,  5 );
  R( d, e, a, b, c, F4, K4,  9, 11 );
  R( c, d, e, a, b, F4, K4,  7,  6 );
  R( b, c, d, e, a, F4, K4, 12,  8 );
  R( a, b, c, d, e, F4, K4,  2, 13 );
  R( e, a, b, c, d, F4, K4, 10, 12 );
  R( d, e, a, b, c, F4, K4, 14,  5 );
  R( c, d, e, a, b, F4, K4,  1, 12 );
  R( b, c, d, e, a, F4, K4,  3, 13 );
  R( a, b, c, d, e, F4, K4,  8, 14 );
  R( e, a, b, c, d, F4, K4, 11, 11 );
  R( d, e, a, b, c, F4, K4,  6,  8 );
  R( c, d, e, a, b, F4, K4, 15,  5 );
  R( b, c, d, e, a, F4, K4, 13,  6 );

  aa = a; bb = b; cc = c; dd = d; ee = e;

  /* Right lane.  */
  a = hd->h0;
  b = hd->h1;
  c = hd->h2;
  d = hd->h3;
  e = hd->h4;
  R( a, b, c, d, e, F4, KK0,	5,  8);
  R( e, a, b, c, d, F4, KK0, 14,  9);
  R( d, e, a, b, c, F4, KK0,	7,  9);
  R( c, d, e, a, b, F4, KK0,	0, 11);
  R( b, c, d, e, a, F4, KK0,	9, 13);
  R( a, b, c, d, e, F4, KK0,	2, 15);
  R( e, a, b, c, d, F4, KK0, 11, 15);
  R( d, e, a, b, c, F4, KK0,	4,  5);
  R( c, d, e, a, b, F4, KK0, 13,  7);
  R( b, c, d, e, a, F4, KK0,	6,  7);
  R( a, b, c, d, e, F4, KK0, 15,  8);
  R( e, a, b, c, d, F4, KK0,	8, 11);
  R( d, e, a, b, c, F4, KK0,	1, 14);
  R( c, d, e, a, b, F4, KK0, 10, 14);
  R( b, c, d, e, a, F4, KK0,	3, 12);
  R( a, b, c, d, e, F4, KK0, 12,  6);
  R( e, a, b, c, d, F3, KK1,	6,  9);
  R( d, e, a, b, c, F3, KK1, 11, 13);
  R( c, d, e, a, b, F3, KK1,	3, 15);
  R( b, c, d, e, a, F3, KK1,	7,  7);
  R( a, b, c, d, e, F3, KK1,	0, 12);
  R( e, a, b, c, d, F3, KK1, 13,  8);
  R( d, e, a, b, c, F3, KK1,	5,  9);
  R( c, d, e, a, b, F3, KK1, 10, 11);
  R( b, c, d, e, a, F3, KK1, 14,  7);
  R( a, b, c, d, e, F3, KK1, 15,  7);
  R( e, a, b, c, d, F3, KK1,	8, 12);
  R( d, e, a, b, c, F3, KK1, 12,  7);
  R( c, d, e, a, b, F3, KK1,	4,  6);
  R( b, c, d, e, a, F3, KK1,	9, 15);
  R( a, b, c, d, e, F3, KK1,	1, 13);
  R( e, a, b, c, d, F3, KK1,	2, 11);
  R( d, e, a, b, c, F2, KK2, 15,  9);
  R( c, d, e, a, b, F2, KK2,	5,  7);
  R( b, c, d, e, a, F2, KK2,	1, 15);
  R( a, b, c, d, e, F2, KK2,	3, 11);
  R( e, a, b, c, d, F2, KK2,	7,  8);
  R( d, e, a, b, c, F2, KK2, 14,  6);
  R( c, d, e, a, b, F2, KK2,	6,  6);
  R( b, c, d, e, a, F2, KK2,	9, 14);
  R( a, b, c, d, e, F2, KK2, 11, 12);
  R( e, a, b, c, d, F2, KK2,	8, 13);
  R( d, e, a, b, c, F2, KK2, 12,  5);
  R( c, d, e, a, b, F2, KK2,	2, 14);
  R( b, c, d, e, a, F2, KK2, 10, 13);
  R( a, b, c, d, e, F2, KK2,	0, 13);
  R( e, a, b, c, d, F2, KK2,	4,  7);
  R( d, e, a, b, c, F2, KK2, 13,  5);
  R( c, d, e, a, b, F1, KK3,	8, 15);
  R( b, c, d, e, a, F1, KK3,	6,  5);
  R( a, b, c, d, e, F1, KK3,	4,  8);
  R( e, a, b, c, d, F1, KK3,	1, 11);
  R( d, e, a, b, c, F1, KK3,	3, 14);
  R( c, d, e, a, b, F1, KK3, 11, 14);
  R( b, c, d, e, a, F1, KK3, 15,  6);
  R( a, b, c, d, e, F1, KK3,	0, 14);
  R( e, a, b, c, d, F1, KK3,	5,  6);
  R( d, e, a, b, c, F1, KK3, 12,  9);
  R( c, d, e, a, b, F1, KK3,	2, 12);
  R( b, c, d, e, a, F1, KK3, 13,  9);
  R( a, b, c, d, e, F1, KK3,	9, 12);
  R( e, a, b, c, d, F1, KK3,	7,  5);
  R( d, e, a, b, c, F1, KK3, 10, 15);
  R( c, d, e, a, b, F1, KK3, 14,  8);
  R( b, c, d, e, a, F0, KK4, 12,  8);
  R( a, b, c, d, e, F0, KK4, 15,  5);
  R( e, a, b, c, d, F0, KK4, 10, 12);
  R( d, e, a, b, c, F0, KK4,	4,  9);
  R( c, d, e, a, b, F0, KK4,	1, 12);
  R( b, c, d, e, a, F0, KK4,	5,  5);
  R( a, b, c, d, e, F0, KK4,	8, 14);
  R( e, a, b, c, d, F0, KK4,	7,  6);
  R( d, e, a, b, c, F0, KK4,	6,  8);
  R( c, d, e, a, b, F0, KK4,	2, 13);
  R( b, c, d, e, a, F0, KK4, 13,  6);
  R( a, b, c, d, e, F0, KK4, 14,  5);
  R( e, a, b, c, d, F0, KK4,	0, 15);
  R( d, e, a, b, c, F0, KK4,	3, 13);
  R( c, d, e, a, b, F0, KK4,	9, 11);
  R( b, c, d, e, a, F0, KK4, 11, 11);


  t	 = hd->h1 + d + cc;
  hd->h1 = hd->h2 + e + dd;
  hd->h2 = hd->h3 + a + ee;
  hd->h3 = hd->h4 + b + aa;
  hd->h4 = hd->h0 + c + bb;
  hd->h0 = t;
}


/* Update the message digest with the content of (INBUF,INLEN).  */
static void
rmd160_write (rmd160_context_t *hd, const unsigned char *inbuf, size_t inlen)
{
  if( hd->count == 64 )
    {
      /* Flush the buffer.  */
      transform (hd, hd->buf);
      hd->count = 0;
      hd->nblocks++;
    }
  if (!inbuf)
    return;

  if (hd->count)
    {
      for (; inlen && hd->count < 64; inlen--)
        hd->buf[hd->count++] = *inbuf++;
      rmd160_write (hd, NULL, 0);
      if (!inlen)
        return;
    }

  while (inlen >= 64)
    {
      transform (hd, inbuf);
      hd->count = 0;
      hd->nblocks++;
      inlen -= 64;
      inbuf += 64;
    }
  for (; inlen && hd->count < 64; inlen--)
    hd->buf[hd->count++] = *inbuf++;
}


/* Complete the message computation.  */
static void
rmd160_final( rmd160_context_t *hd )
{
  uint32_t t, msb, lsb;
  unsigned char *p;

  rmd160_write (hd, NULL, 0); /* Flush buffer. */

  t = hd->nblocks;
  /* Multiply by 64 to make a byte count. */
  lsb = t << 6;
  msb = t >> 26;
  /* Add the count.  */
  t = lsb;
  if ((lsb += hd->count) < t)
    msb++;
  /* Multiply by 8 to make a bit count.  */
  t = lsb;
  lsb <<= 3;
  msb <<= 3;
  msb |= t >> 29;

  if (hd->count < 56)
    {
      /* Enough room.  */
      hd->buf[hd->count++] = 0x80; /* Pad character. */
      while (hd->count < 56)
        hd->buf[hd->count++] = 0;
    }
  else
    {
      /* Need one extra block.  */
      hd->buf[hd->count++] = 0x80; /* Pad character. */
      while (hd->count < 64)
        hd->buf[hd->count++] = 0;
      rmd160_write (hd, NULL, 0); /* Flush buffer.  */
      memset (hd->buf, 0, 56);    /* Fill next block with zeroes.  */
    }
  /* Append the 64 bit count.  */
  hd->buf[56] = lsb;
  hd->buf[57] = lsb >>  8;
  hd->buf[58] = lsb >> 16;
  hd->buf[59] = lsb >> 24;
  hd->buf[60] = msb;
  hd->buf[61] = msb >>  8;
  hd->buf[62] = msb >> 16;
  hd->buf[63] = msb >> 24;
  transform (hd, hd->buf);

  p = hd->buf;
#define X(a) do { *p++ = hd->h##a;       *p++ = hd->h##a >> 8;	\
                  *p++ = hd->h##a >> 16; *p++ = hd->h##a >> 24; } while(0)
  X(0);
  X(1);
  X(2);
  X(3);
  X(4);
#undef X
}


/*
 * Combined function to put the hash value of the supplied BUFFER into
 * OUTBUF which must have a size of 20 bytes.  IF the global SALT is
 * given hash that value also.  Note, we use RMD160 only because it
 * was the easiest available source for a hash fucntion.  It does not
 * matter what hash function we use; it is only for obfuscating the
 * domain name.
 */
void
rmd160_hash_buffer (void *outbuf, const void *buffer, size_t length)
{
  rmd160_context_t hd;

  rmd160_init (&hd);
  if (salt)
    rmd160_write (&hd, salt, strlen (salt));
  rmd160_write (&hd, buffer, length);
  rmd160_final (&hd);
  memcpy (outbuf, hd.buf, 20);
}


/* Expand an IPv6 address string by inserting missing '0', changing
   letters to lowercase, and removing the the colons.  Returns a
   pointer to a static buffer or NULL on error.  Example:
   "2001:aA8:fff1:2100::60" gives
   "20010aa8fff121000000000000000060".  */
static char *
expand_v6 (const char *addrstr)
{
  static char buffer[32+1];
  char tmpbuf[4];
  int tmpidx, idx, i;
  const char *s;
  int ncolon;

  for (s=addrstr, ncolon=0; *s && !sensible_ctype (isspace, *s); s++)
    {
      if (*s == ':')
        ncolon++;
    }
  if (ncolon > 8)
    return NULL;  /* Oops.  */

  memset (buffer, '0', 32);
  buffer[32] = 0;
  idx = tmpidx = 0;
  for (s=addrstr; *s && !sensible_ctype (isspace, *s); s++)
    {
      if (*s == ':')
        {
          idx += 4 - tmpidx;
          for (i=0; i < tmpidx; i++)
            {
              if (idx >= sizeof buffer)
                return NULL;
              buffer[idx++] = tmpbuf[i];
            }
          tmpidx = 0;
          if (s[1] == ':') /* Double colon.  */
            {
              s++;
              if (!ncolon || s[1] == ':')
                return NULL;  /* More than one double colon. */
              idx += 4*(8 - ncolon);
              ncolon = 0;
            }
        }
      else if (tmpidx > 3)
        return NULL;  /* Invalid address.  */
      else if (!sensible_ctype (isxdigit, *s))
        return NULL;  /* Invalid character.  */
      else
        tmpbuf[tmpidx++] = sensible_ctype (tolower, *s);
    }

  idx += 4 - tmpidx;
  for (i=0; i < tmpidx; i++)
    {
      if (idx >= sizeof buffer)
        return NULL;
      buffer[idx++] = tmpbuf[i];
    }

  return buffer;
}


/*
 * Parse the IP address and convert to a reverse domain name.  On
 * return the full IP address is stored at FULLIP which is
 * expected to be a buffer of at least FULLIPBUFLEN bytes.
 */
static char *
ipaddr2domain(char *start, char **addr, char **rest, char *fullip,
              int *r_is_v6, int opts)
{
  /* Sample values BUF needs to hold:
   * "123.123.123.123.in-addr.arpa."
   * "0.6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.2.1.f.f.f.8.a.a.0.1.0.0.2.ip6.arpa."
   */
  static char buf[74];
  int i;
  char *endp;
  int ndots = 0;

  *r_is_v6 = 0;

  /* Better skip leading spaces which might have been create by some
     log processing scripts.  */
  while (sensible_ctype(isspace, *start))
    start++;

  if ((opts & OPT_VHOST))
    {
      while (!sensible_ctype(isspace, *start))
        start++;
      while (sensible_ctype(isspace, *start))
        start++;
    }

  for (endp = start; !sensible_ctype(isspace, *endp); endp++)
    {
      if (*endp == ':')
        *r_is_v6 = 1;
      else if (*endp == '.')
        ndots++;
    }
  if (endp == start)
    {
      strcpy (buf, "invalid");
      *addr = *rest = NULL;
      goto leave;
    }

  if (*r_is_v6)
    {
      const char *exp = expand_v6 (start);
      const char *s;
      char *p;
      size_t len;

      if (!exp)
        {
          strcpy (buf, "invalid_v6");
          *addr = *rest = NULL;
          goto leave;
        }

      len = strlen (exp);
      assert (len + 9 + 1 <= sizeof buf);
      assert (len < FULLIPBUFLEN);
      strcpy (fullip, exp);

      p = buf;
      for (s = exp + len - 1; s >= exp; s--)
        {
          *p++ = *s;
          *p++ = '.';
        }
      strcpy (p, "ip6.arpa.");
      *addr = start;
      *rest = endp;
    }
  else /* v4 */
    {
      char *ptrs[5];

      /* Largest expected string is "255.255.255.255".  */
      if ((endp - start) > 15 || ndots != 3)
        {
          strcpy (buf, "invalid_v4");
          *addr = *rest = NULL;
          goto leave;
        }
      snprintf (fullip, FULLIPBUFLEN, "%.*s", (int)(endp-start), start);

      ptrs[0] = start;
      for (i = 1; i < 5; i++)
        {
          ptrs[i] = ptrs[i-1];
          while (sensible_ctype (isdigit, *ptrs[i]++))
            ;
          if ((i == 4 && !sensible_ctype (isspace, ptrs[i][-1]))
              || (i != 4 && ptrs[i][-1] != '.')
              || (ptrs[i]-ptrs[i-1] > 4)
              || (i!=4 && !sensible_ctype (isdigit, ptrs[i][0])))
            {
              strcpy (buf, "invalid_v4");
              *addr = *rest = NULL;
              goto leave;
            }
        }

      snprintf (buf, sizeof buf, "%.*s.%.*s.%.*s.%.*s.in-addr.arpa.",
                (int)(ptrs[4]-ptrs[3]-1), ptrs[3],
                (int)(ptrs[3]-ptrs[2]-1), ptrs[2],
                (int)(ptrs[2]-ptrs[1]-1), ptrs[1],
                (int)(ptrs[1]-ptrs[0]-1), ptrs[0]);
      *addr= ptrs[0];
      *rest= ptrs[4]-1;
    }

 leave:
  return buf;
}

static void
printline(FILE *outf, char *start, char *addr, char *rest, const char *domain,
          const char *fullip, int is_v6, int opts)
{
  int append_null = 0;

  if ((opts & OPT_PRIVACY) && !domain && *fullip)
    {
      domain = fullip;
      append_null = 1;
    }

  if (domain)
    {
      const char *p;

      p = append_null? ".null" : strrchr (domain, '.');
      if ((opts & OPT_PRIVACY) && p && p[1])
        {
          unsigned char hash[20];
          int i;

          rmd160_hash_buffer (hash, domain, strlen (domain));
          fprintf (outf, "%.*sp", (int)(addr - start), start);
          for (i=0; i < 4; i++)
            fprintf (outf, "%02x", hash[i]);
          fprintf(outf, "%c%s%s", is_v6? '6':'4', p, rest);
        }
      else
        fprintf(outf, "%.*s%s%s", (int)(addr - start), start, domain, rest);
    }
  else
    fputs(start, outf);

  if (ferror(outf))
    aargh("write output");
}

typedef struct logline {
  struct logline *next;
  char *start, *addr, *rest;
  char fullip[FULLIPBUFLEN];
  int is_v6;
  adns_query query;
} logline;

static logline *readline(FILE *inf, adns_state adns, int opts) {
  static char buf[MAXLINE];
  char *str;
  logline *line;

  if (fgets(buf, MAXLINE, inf)) {
    str= malloc(sizeof(*line) + strlen(buf) + 1);
    if (!str) aargh("malloc");
    line= (logline*)str;
    line->next= NULL;
    line->start= str+sizeof(logline);
    line->is_v6 = 0;
    *line->fullip = 0;
    strcpy(line->start, buf);
    str= ipaddr2domain(line->start, &line->addr, &line->rest, line->fullip,
                       &line->is_v6, opts);
    if (opts & OPT_DEBUG)
      msg("submitting %.*s -> %s", (int)(line->rest-line->addr), guard_null(line->addr), str);
    /* Note: ADNS does not yet support "ptr" for IPv6.  */
    if (adns_submit(adns, str,
                    line->is_v6? adns_r_ptr_raw : adns_r_ptr,
		    adns_qf_quoteok_cname|adns_qf_cname_loose,
		    NULL, &line->query))
      aargh("adns_submit");
    return line;
  }
  if (!feof(inf))
    aargh("fgets");
  return NULL;
}

static void proclog(FILE *inf, FILE *outf, int maxpending, int opts) {
  int eof, err, len;
  adns_state adns;
  adns_answer *answer;
  logline *head, *tail, *line;
  adns_initflags initflags;

  initflags= (opts & OPT_DEBUG) ? adns_if_debug : 0;
  if (config_text) {
    errno= adns_init_strcfg(&adns, initflags, stderr, config_text);
  } else {
    errno= adns_init(&adns, initflags, 0);
  }
  if (errno) aargh("adns_init");
  head= tail= readline(inf, adns, opts);
  len= 1; eof= 0;
  while (head) {
    while (head) {
      if (opts & OPT_DEBUG)
	msg("%d in queue; checking %.*s", len,
	    (int)(head->rest-head->addr), guard_null(head->addr));
      if (eof || len >= maxpending) {
	if (opts & OPT_POLL)
	  err= adns_wait_poll(adns, &head->query, &answer, NULL);
	else
	  err= adns_wait(adns, &head->query, &answer, NULL);
      } else {
	err= adns_check(adns, &head->query, &answer, NULL);
      }
      if (err == EAGAIN) break;
      if (err) {
	fprintf(stderr, "%s: adns_wait/check: %s", progname, strerror(err));
	exit(1);
      }
      printline(outf, head->start, head->addr, head->rest,
		answer->status == adns_s_ok ? *answer->rrs.str : NULL,
                head->fullip, head->is_v6, opts);
      line= head; head= head->next;
      free(line);
      free(answer);
      len--;
    }
    if (!eof) {
      line= readline(inf, adns, opts);
      if (line) {
        if (!head) head= line;
        else tail->next= line;
        tail= line; len++;
      } else {
	eof= 1;
      }
    }
  }
  adns_finish(adns);
}

static void printhelp(FILE *file) {
  fputs("usage: adnslogres [<options>] [<logfile>]\n"
	"       adnslogres --version|--help\n"
	"options: -c <concurrency>  set max number of outstanding queries\n"
	"         -p                use poll(2) instead of select(2)\n"
	"         -d                turn on debugging\n"
        "         -P                privacy mode\n"
        "         -x                first field is the virtual host\n"
        "         -S <salt>         salt for the privacy mode\n"
	"         -C <config>       use instead of contents of resolv.conf\n"
        "\n"
        "The privacy mode replaces addresses by a 32 bit hash value.\n"
        "A daily salt should be used to make testing for addresses hard.\n",
	stdout);
}

static void usage(void) {
  printhelp(stderr);
  exit(1);
}

int main(int argc, char *argv[]) {
  int c, opts, maxpending;
  extern char *optarg;
  FILE *inf;

  if (argv[1] && !strncmp(argv[1],"--",2)) {
    if (!strcmp(argv[1],"--help")) {
      printhelp(stdout);
    } else if (!strcmp(argv[1],"--version")) {
      fputs(VERSION_MESSAGE("adnslogres"),stdout);
    } else {
      usage();
    }
    if (ferror(stdout) || fclose(stdout)) { perror("stdout"); exit(1); }
    exit(0);
  }

  maxpending= DEFMAXPENDING;
  opts= 0;
  while ((c= getopt(argc, argv, "c:C:dxpPS:")) != -1)
    switch (c) {
    case 'c':
      maxpending= atoi(optarg);
      if (maxpending < 1 || maxpending > MAXMAXPENDING) {
       fprintf(stderr, "%s: unfeasible concurrency %d\n", progname, maxpending);
       exit(1);
      }
      break;
    case 'C':
      config_text= optarg;
      break;
    case 'd':
      opts|= OPT_DEBUG;
      break;
    case 'x':
      opts|= OPT_VHOST;
      break;
    case 'P':
      opts|= OPT_PRIVACY;
      break;
    case 'S':
      salt = optarg;
      break;
    default:
      usage();
    }

  argc-= optind;
  argv+= optind;

  inf= NULL;
  if (argc == 0)
    inf= stdin;
  else if (argc == 1)
    inf= fopen(*argv, "r");
  else
    usage();

  if (!inf)
    aargh("couldn't open input");

  proclog(inf, stdout, maxpending, opts);

  if (fclose(inf))
    aargh("fclose input");
  if (fclose(stdout))
    aargh("fclose output");

  return 0;
}
