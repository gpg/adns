/**/

#include "adns-internal.h"

static adns_query allocquery(adns_state ads, const char *owner, int ol,
			     int qml, int id, adns_rrtype type,
			     adns_queryflags flags, void *context) {
  adns_query qu;
  unsigned char *qm;
  
  qu= malloc(sizeof(*qu)+ol+1+qml); if (!qu) return 0;
  qu->next= qu->back= qu->parent= 0;
  qu->children.head= qu->children.tail= 0;
  qu->siblings.next= qu->siblings.back= 0;
  qu->id= id;
  qu->type= type;
  qu->answer= 0;
  qu->flags= flags;
  qu->context= context;
  qu->udpretries= 0;
  qu->sentudp= qu->senttcp= 0;
  qu->nextserver= 0;
  memcpy(qu->owner,owner,ol); qu->owner[ol]= 0;
  qu->querymsg= qm= qu->owner+ol+1;
  memcpy(qm,ads->qbuf,qml);
  qu->querylen= qml;
  return qu;
}

static int failsubmit(adns_state ads, void *context, adns_query *query_r,
		      adns_rrtype type, adns_queryflags flags,
		      int id, adns_status stat) {
  adns_query qu;

  qu= allocquery(ads,0,0,0,id,type,flags,context); if (!qu) return errno;
  query_fail(ads,qu,stat);
  *query_r= qu;
  return 0;
}

int adns_submit(adns_state ads,
		const char *owner,
		adns_rrtype type,
		adns_queryflags flags,
		void *context,
		adns_query *query_r) {
  adns_query qu;
  adns_status stat;
  int ol, id, qml;

  id= ads->nextid++;

  ol= strlen(owner);
  if (ol<=1 || ol>MAXDNAME+1)
    return failsubmit(ads,context,query_r,type,flags,id,adns_s_invaliddomain);
  if (owner[ol-1]=='.' && owner[ol-2]!='\\') { flags &= ~adns_f_search; ol--; }

  stat= mkquery(ads,owner,ol,id,type,flags,&qml);
  if (stat) return failsubmit(ads,context,query_r,type,flags,id,stat);

  qu= allocquery(ads,owner,ol,qml,id,type,flags,context); if (!qu) return errno;
  if (qu->flags & adns_f_usevc) qu->udpretries= -1;
  LIST_LINK_TAIL(ads->tosend,qu);
    
  r= gettimeofday(&now,0); if (r) return;
  quproc_tosend(ads,qu,now);
  autosys(ads,now);

  *query_r= qu;
  return 0;
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
  abort(); /* FIXME */
}
