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
#include <assert.h>
#include <stdlib.h>

#include "adns.h"

static void failure(const char *what, adns_status st) {
  fprintf(stderr,"adns failure: %s: %s\n",what,adns_strerror(st));
  exit(2);
}

static const char *defaultargv[]= { "ns.chiark.greenend.org.uk", 0 };

int main(int argc, const char *const *argv) {
  adns_state ads;
  adns_query *qus, qu;
  adns_answer *ans;
  const char *rrtn, *fmtn;
  char *show;
  int len, i, qc, qi;
  adns_status r, ri;

  if (argv[0] && argv[1]) argv++;
  else argv= defaultargv;

  for (qc=0; qc[argv]; qc++);
  qus= malloc(sizeof(qus)*qc);
  if (!qus) { perror("malloc qus"); exit(3); }

  r= adns_init(&ads,adns_if_debug|adns_if_noautosys,0);
  if (r) failure("init",r);

  for (qi=0; qi<qc; qi++) {
    r= adns_submit(ads,argv[qi],adns_r_a,0,0,&qus[qi]);
    if (r) failure("submit",r);
  }

  for (qi=0; qi<qc; qi++) {
    qu= qus[qi];
    r= adns_wait(ads,&qu,&ans,0);
    if (r) failure("wait",r);

    ri= adns_rr_info(ans->type, &rrtn,&fmtn,&len, 0,0);
    fprintf(stdout, "%s: %s; nrrs=%d; cname=%s; ",
	    argv[qi], adns_strerror(ans->status),
	    ans->nrrs, ans->cname ? ans->cname : "$");
    fprintf(stdout, "type %s(%s) %s\n",
	    ri ? "?" : rrtn, ri ? "?" : fmtn ? fmtn : "-",
	    adns_strerror(ri));
    if (ans->nrrs) {
      assert(!ri);
      for (i=0; i<ans->nrrs; i++) {
	r= adns_rr_info(ans->type, 0,0,0, ans->rrs.bytes+i*len,&show);
	if (r) failure("info",r);
	printf(" %s\n",show);
	free(show);
      }
    }
    free(ans);
  }

  free(qus);
  exit(0);
}
