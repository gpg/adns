/*
 * dtest.c
 * - simple test program, not part of the library
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

#include <stdio.h>
#include <unistd.h>

#include "adns.h"

int main(void) {
  adns_state ads;
  adns_query qu;
  adns_answer *ans;
  int r;

  r= adns_init(&ads,adns_if_debug|adns_if_noautosys,0);
  if (r) { perror("init"); exit(2); }

  r= adns_submit(ads,"anarres.relativity.greenend.org.uk",adns_r_a,0,0,&qu);
  if (r) { perror("submit"); exit(2); }

  r= adns_wait(ads,&qu,&ans,0);
  if (r) { perror("wait"); exit(2); }

  fprintf(stderr,"answer status %d type %d rrs %d cname %s\n",
	  ans->status,ans->type,ans->nrrs,
	  ans->cname ? ans->cname : "-");
  
  exit(0);
}
