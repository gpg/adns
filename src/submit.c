/**/

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/time.h>

#include "internal.h"

int adns__internal_submit(adns_state ads, adns_query *query_r,
			  adns_rrtype type, char *query_dgram, int query_len,
			  adns_queryflags flags, struct timeval now,
			  adns_status failstat, const qcontext *ctx) {
  /* Submits a query (for internal use, called during external submits).
   *
   * The new query is returned in *query_r, or we return adns_s_nomemory.
   *
   * The query datagram should already have been assembled; memory for it
   * is taken over by this routine whether it succeeds or fails.
   *
   * If failstat is nonzero then if we are successful in creating the query
   * it is immediately failed with code failstat (but _submit still succeds).
   *
   * ctx is copied byte-for-byte into the query.
   */
  adns_query qu;
  adns_status stat;
  int ol, id, r;
  struct timeval now;
  const typeinfo *typei;
  adns_query qu;

  id= ads->nextid++;

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
  qu->query_dgram= query_dgram;
  qu->query_dglen= query_dglen;
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

  *query_r= qu;

  if (qu->typei) {
    qu->answer->rrsz= qu->rrsz;
  } else {
    qu->answer->rrsz= -1;
    failstat= adns_s_notimplemented;
  }
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

  ctx.ext= context;
  r= gettimeofday(&now,0); if (r) return errno;

  ol= strlen(owner);
  if (ol<=1 || ol>DNS_MAXDOMAIN+1)
    return failsubmit(ads,context,query_r,flags,id,adns_s_invaliddomain);
  if (owner[ol-1]=='.' && owner[ol-2]!='\\') { flags &= ~adns_qf_search; ol--; }

  stat= adns__mkquery(ads,owner,ol,id,typei,flags);
  if (stat) return failsubmit(ads,context,query_r,flags,id,stat);
  
  adns__internal_submit(ads,type,flags,now,query_r
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

void *adns__alloc_interim(adns_state ads, adns_query qu, size_t sz) {
  allocnode *an;

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
