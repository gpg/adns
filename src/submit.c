/**/

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/time.h>

#include "internal.h"

int adns__internal_submit(adns_state ads, adns_query *query_r,
			  adns_rrtype type, vbuf *qumsg_vb, int id,
			  adns_queryflags flags, struct timeval now,
			  adns_status failstat, const qcontext *ctx) {
  adns_query qu;
  adns_status stat;
  int ol, id, r;
  struct timeval now;
  const typeinfo *typei;
  adns_query qu;

  qu= malloc(sizeof(*qu)); if (!qu) goto x_nomemory;
  qu->answer= malloc(sizeof(*qu->answer)); if (!qu->answer) goto x_freequ_nomemory;

  qu->state= query_udp;
  qu->back= qu->next= qu->parent= 0;
  LIST_INIT(qu->children);
  qu->siblings.next= qu->siblings.back= 0;
  qu->allocations= 0;
  qu->interim_allocd= 0;
  qu->perm_used= 0;

  qu->typei= adns__findtype(type);
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
  memcpy(qu->owner,owner,ol); qu->owner[ol]= 0;

  qu->answer->status= adns_s_ok;
  qu->answer->cname= 0;
  qu->answer->type= type;
  qu->answer->nrrs= 0;
  qu->answer->rrs= 0;

  if (qu->typei) {
    qu->answer->rrsz= qu->rrsz;
  } else {
    qu->answer->rrsz= -1;
    failstat= adns_s_notimplemented;
  }
  
  *query_r= qu;

  qu->query_dgram= malloc(qumsg_vb->used);
  if (!qu->query_dgram) {
    adns__query_fail(ads,qu,adns_s_nomemory);
    return;
  }
  memcpy(qu->query_dgram,qumsg_vb->buf,qumsg_vb->used);
  qu->vb= *qumsg_vb;
  adns__vbuf_init(qumsg_vb);
  
  if (failstat) {
    adns__query_fail(ads,qu,failstat);
    return;
  }
  adns__query_udp(ads,qu,now);
  adns__autosys(ads,now);

  return 0;

 x_freequ_nomemory:
  free(qu);
 x_nomemory:
  free(query_dgram);
  return adns_s_nomemory;
}

int adns_submit(adns_state ads,
		const char *owner,
		adns_rrtype type,
		adns_queryflags flags,
		void *context,
		adns_query *query_r) {
  qcontext ctx;
  int id;
  vbuf vb;

  ctx.ext= context;
  r= gettimeofday(&now,0); if (r) return errno;
  id= 0;

  adns__vbuf_init(&vb);

  ol= strlen(owner);
  if (ol<=1 || ol>DNS_MAXDOMAIN+1) { stat= adns_s_invaliddomain; goto xit; }
				 
  if (owner[ol-1]=='.' && owner[ol-2]!='\\') { flags &= ~adns_qf_search; ol--; }

  stat= adns__mkquery(ads,&vb, &id, owner,ol, typei,flags);
			
 xit:
  return adns__internal_submit(ads,query_r, type,&vb,id, flags,now, stat,&ctx);	
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
  if (r) adns_cancel(ads,qu);
  return r;
}

void adns_cancel(adns_state ads, adns_query query) {
  abort(); /* fixme */
}

void adns__makefinal_str(adns_query qu, char **strp) {
  int l;
  char *before, *after;

  before= *strp;
  l= strlen(before)+1;
  after= adns__alloc_final(qu,l);
  memcpy(after,before,l);
  *strp= after;  
}

void adns__makefinal_block(adns__query qu, void **blpp, size_t sz) {
  void *after;

  after= adns__alloc_final(qu,sz);
  memcpy(after,*blpp,sz);
  *blpp= after;
}

void *adns__alloc_interim(adns_state ads, adns_query qu, size_t sz) {
  allocnode *an;

  assert(!qu->final_allocspace);
  sz= MEM_ROUND(sz);
  an= malloc(MEM_ROUND(MEM_ROUND(sizeof(*an)) + sz));
  if (!an) {
    adns__query_fail(ads,qu,adns_s_nolocalmem);
    return 0;
  }
  qu->permalloclen += sz;
  an->next= qu->allocations;
  qu->allocations= an;
  return (byte*)an + MEM_ROUND(sizeof(*an));
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
