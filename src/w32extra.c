/*
 * w32extra.c
 * - Utitliy functions for Windows.
 */
/*
 *  This file is
 *    Copyright (C) 2008 g10 Code GmbH
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



/* Taken from the mingw32 runtime 3.12:
 * gettimeofday
 * Implementation according to:
 * The Open Group Base Specifications Issue 6
 * IEEE Std 1003.1, 2004 Edition
 */
  
/*
 *  THIS SOFTWARE IS NOT COPYRIGHTED
 *
 *  This source code is offered for use in the public domain. You may
 *  use, modify or distribute it freely.
 *
 *  This code is distributed in the hope that it will be useful but
 *  WITHOUT ANY WARRANTY. ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
 *  DISCLAIMED. This includes but is not limited to warranties of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  Contributed by:
 *  Danny Smith <dannysmith@users.sourceforge.net>
 */
#ifndef HAVE_GETTIMEOFDAY
int
gettimeofday (struct timeval *__restrict__ tp, void *__restrict__ tzp)
 {
   /* Offset between 1/1/1601 and 1/1/1970 in 100 nanosec units */
# define _W32_FT_OFFSET (116444736000000000ULL)

  union {
    unsigned long long ns100; /*time since 1 Jan 1601 in 100ns units */
    FILETIME ft;
  }  _now;

  (void)tzp;

  if(tp)
    {
      GetSystemTimeAsFileTime (&_now.ft);
      tp->tv_usec=(long)((_now.ns100 / 10ULL) % 1000000ULL );
      tp->tv_sec= (long)((_now.ns100 - _W32_FT_OFFSET) / 10000000ULL);
    }
  /* Always return 0 as per Open Group Base Specifications Issue 6.
     Do not set errno on error.  */
  return 0;
}
#endif



/* Implementation of the nrand48 function.  [Taken from glibc 2.6.
   Copyright (C) 1995, 1996, 2001 Free Software Foundation, Inc.] */

struct drand48_data
  {
    unsigned short int x[3];	/* Current state.  */
    unsigned short int old_x[3]; /* Old state.  */
    unsigned short int c;	/* Additive const. in congruential formula.  */
    unsigned short int init;	/* Flag for initializing.  */
    unsigned long long int a;	/* Factor in congruential formula.  */
  };


/* Global state for rand fucntions.  */
static struct drand48_data my_drand48_data;

static int
drand48_iterate (unsigned short int xsubi[3], struct drand48_data *buffer)
{
  uint64_t X;
  uint64_t result;

  /* Initialize buffer, if not yet done.  */
  if (!buffer->init)
    {
      buffer->a = 0x5deece66dull;
      buffer->c = 0xb;
      buffer->init = 1;
    }

  /* Do the real work.  We choose a data type which contains at least
     48 bits.  Because we compute the modulus it does not care how
     many bits really are computed.  */

  X = (uint64_t) xsubi[2] << 32 | (uint32_t) xsubi[1] << 16 | xsubi[0];

  result = X * buffer->a + buffer->c;

  xsubi[0] = result & 0xffff;
  xsubi[1] = (result >> 16) & 0xffff;
  xsubi[2] = (result >> 32) & 0xffff;

  return 0;
}

static int
nrand48_r (unsigned short int xsubi[3],
           struct drand48_data *buffer,
           long int *result)
{
  /* Compute next state.  */
  if (drand48_iterate (xsubi, buffer) < 0)
    return -1;

  /* Store the result.  */
  if (sizeof (unsigned short int) == 2)
    *result = xsubi[2] << 15 | xsubi[1] >> 1;
  else
    *result = xsubi[2] >> 1;

  return 0;
}

long int
nrand48 (unsigned short int xsubi[3])
{
  long int result;

  (void) nrand48_r (xsubi, &my_drand48_data, &result);

  return result;
}


