/*
 * query.c
 * - overall query management (allocation, completion)
 * - per-query memory management
 * - query submission and cancellation (user-visible and internal)
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

#include "internal.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/time.h>

#include "internal.h"

int adns__internal_submit(adns_state ads, adns_query *query_r,
			  const typeinfo *typei, vbuf *qumsg_vb, int id,
			  adns_queryflags flags, struct timeval now,
			  adns_status failstat, const qcontext *ctx) {
  adns_query qu;

  qu= malloc(sizeof(*qu)); if (!qu) goto x_nomemory;
  qu->answer= malloc(sizeof(*qu->answer)); if (!qu->answer) goto x_freequ_nomemory;

  qu->ads= ads;
  qu->state= query_udp;
  qu->back= qu->next= qu->parent= 0;
  LIST_INIT(qu->children);
  qu->siblings.next= qu->siblings.back= 0;
  qu->allocations= 0;
  qu->interim_allocd= 0;
  qu->final_allocspace= 0;

  qu->typei= typei;
  adns__vbuf_init(&qu->vb);

  qu->cname_dgram= 0;
  qu->cname_dglen= qu->cname_begin= 0;
  
  qu->id= id;
  qu->flags= flags;
  qu->udpretries= 0;
  qu->udpnextserver= 0;
  qu->udpsent= qu->tcpfailed= 0;
  timerclear(&qu->timeout);
  memcpy(&qu->context,ctx,sizeof(qu->context));

  qu->answer->status= adns_s_ok;
  qu->answer->cname= 0;
  qu->answer->type= typei->type;
  qu->answer->nrrs= 0;
  qu->answer->rrs= 0;
  qu->answer->rrsz= typei->rrsz;
  
  *query_r= qu;

  qu->query_dglen= qumsg_vb->used;
  if (qumsg_vb->used) {
    qu->query_dgram= malloc(qumsg_vb->used);
    if (!qu->query_dgram) {
      adns__query_fail(qu,adns_s_nolocalmem);
      return adns_s_ok;
    }
    memcpy(qu->query_dgram,qumsg_vb->buf,qumsg_vb->used);
  } else {
    qu->query_dgram= 0;
  }
  qu->vb= *qumsg_vb;
  adns__vbuf_init(qumsg_vb);
  
  if (failstat) {
    adns__query_fail(qu,failstat);
    return adns_s_ok;
  }
  adns__query_udp(qu,now);
  adns__autosys(ads,now);

  return adns_s_ok;

 x_freequ_nomemory:
  free(qu);
 x_nomemory:
  adns__vbuf_free(qumsg_vb);
  return adns_s_nolocalmem;
}

int adns_submit(adns_state ads,
		const char *owner,
		adns_rrtype type,
		adns_queryflags flags,
		void *context,
		adns_query *query_r) {
  qcontext ctx;
  int id, r, ol;
  vbuf vb;
  adns_status stat;
  const typeinfo *typei;
  struct timeval now;

  typei= adns__findtype(type);
  if (!typei) return adns_s_notimplemented;
  
  ctx.ext= context;
  r= gettimeofday(&now,0); if (r) return errno;
  id= 0;

  adns__vbuf_init(&vb);

  ol= strlen(owner);
  if (ol<=1 || ol>DNS_MAXDOMAIN+1) { stat= adns_s_domaintoolong; goto xit; }
				 
  if (owner[ol-1]=='.' && owner[ol-2]!='\\') { flags &= ~adns_qf_search; ol--; }

  stat= adns__mkquery(ads,&vb,&id, owner,ol, typei,flags);
			
 xit:
  return adns__internal_submit(ads,query_r, typei,&vb,id, flags,now, stat,&ctx);	
}

int adns_synchronous(adns_state ads,
		     const char *owner,
		     adns_rrtype type,
		     adns_queryflags flags,
		     adns_answer **answer_r) {
  adns_query qu;
  int r;
  
  r= adns_submit(ads,owner,type,flags,0,&qu);
  if (r) return r;

  do {
    r= adns_wait(ads,&qu,answer_r,0);
  } while (r==EINTR);
  if (r) adns_cancel(qu);
  return r;
}

void adns_cancel(adns_query query) {
  abort(); /* fixme */
}

static void *alloc_common(adns_query qu, size_t sz) {
  allocnode *an;

  if (!sz) return qu; /* Any old pointer will do */
  assert(!qu->final_allocspace);
  an= malloc(MEM_ROUND(MEM_ROUND(sizeof(*an)) + sz));
  if (!an) {
    adns__query_fail(qu,adns_s_nolocalmem);
    return 0;
  }
  an->next= qu->allocations;
  qu->allocations= an;
  return (byte*)an + MEM_ROUND(sizeof(*an));
}

void *adns__alloc_interim(adns_query qu, size_t sz) {
  sz= MEM_ROUND(sz);
  qu->interim_allocd += sz;
  return alloc_common(qu,sz);
}

void *adns__alloc_mine(adns_query qu, size_t sz) {
  return alloc_common(qu,MEM_ROUND(sz));
}

void *adns__alloc_final(adns_query qu, size_t sz) {
  /* When we're in the _final stage, we _subtract_ from interim_alloc'd
   * each allocation, and use final_allocspace to point to the next free
   * bit.
   */
  void *rp;

  sz= MEM_ROUND(sz);
  rp= qu->final_allocspace;
  assert(rp);
  qu->interim_allocd -= sz;
  assert(qu->interim_allocd>=0);
  qu->final_allocspace= (byte*)rp + sz;
  return rp;
}

void adns__reset_cnameonly(adns_query qu) {
  assert(!qu->final_allocspace);
  qu->answer->nrrs= 0;
  qu->answer->rrs= 0;
  qu->interim_allocd= qu->answer->cname ? MEM_ROUND(strlen(qu->answer->cname)+1) : 0;
}

void adns__query_done(adns_query qu) {
  adns_answer *ans;
  allocnode *an, *ann;
  int i;

  qu->answer= ans= realloc(qu->answer,
			   MEM_ROUND(MEM_ROUND(sizeof(*ans)) +
				     qu->interim_allocd));
  qu->final_allocspace= (byte*)qu->answer + MEM_ROUND(sizeof(*ans));

  adns__makefinal_str(qu,&ans->cname);
  if (ans->nrrs) {
    adns__makefinal_block(qu,&ans->rrs.untyped,ans->rrsz*ans->nrrs);
    for (i=0; i<ans->nrrs; i++)
      qu->typei->makefinal(qu,ans->rrs.bytes+ans->rrsz*i);
  }

  for (an= qu->allocations; an; an= ann) { ann= an->next; free(an); }

  adns__vbuf_free(&qu->vb);
  
  qu->id= -1;
  LIST_LINK_TAIL(qu->ads->output,qu);
}

void adns__query_fail(adns_query qu, adns_status stat) {
  adns__reset_cnameonly(qu);
  qu->answer->status= stat;
  adns__query_done(qu);
}

void adns__makefinal_str(adns_query qu, char **strp) {
  int l;
  char *before, *after;

  before= *strp;
  if (!before) return;
  l= strlen(before)+1;
  after= adns__alloc_final(qu,l);
  memcpy(after,before,l);
  *strp= after;  
}

void adns__makefinal_block(adns_query qu, void **blpp, size_t sz) {
  void *before, *after;

  before= *blpp;
  if (!before) return;
  after= adns__alloc_final(qu,sz);
  memcpy(after,before,sz);
  *blpp= after;
}

