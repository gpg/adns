/**/

#include <arpa/nameser.h>

#include "adns-internal.h"

#define LIST_UNLINK(list,node) \
  do { \
    if ((node)->back) (node)->back->next= (node)->next; \
      else                   (list).head= (node)->next; \
    if ((node)->next) (node)->next->back= (node)->back; \
      else                   (list).tail= (node)->back; \
  } while(0)

#define LIST_LINK_TAIL(list,node) \
  do { \
    (node)->back= 0; \
    (node)->next= (list).tail; \
    if (list).tail (list).tail->back= (node); else (list).head= (node); \
    (list).tail= (node); \
  } while(0)

void addserver(adns_state ads, struct in_addr addr) {
  if (ads->nservers>=MAXSERVERS) {
    if (ads->flags & adns_if_debug)
      fprintf(stderr,"adns: too many nameservers, ignoring %s",
	      inet_ntoa(addr));
  } else {
    ads->servers[ads->nservers].addr= addr;
    ads->servers[ads->nservers].tcpsocket= -1;
    ads->nservers++;
  }
}

void readconfig(adns_state ads, const char *filename) {
}

void readconfigenv(adns_state ads, const char *envvar) {
  const char *filename;

  if (flags & adns_if_noenv) return;
  filename= getenv(envvar); if (!filename) return;
  readconfig(ads,filename);
}
  
int adns_init(adns_state *ads_r, int flags) {
  adns_state ads;
  const char *cfile;
  
  ads= malloc(sizeof(*ads)); if (!ads) return errno;
  ads->queue.head= ads->queue.tail= 0;
  ads->timew.head= ads->timew.tail= 0;
  ads->child.head= ads->child.tail= 0;
  ads->ready.head= ads->ready.tail= 0;
  ads->udpsocket= -1;
  ads->qbufavail= 0;
  ads->qbuf= 0;
  ads->tcpbufavail= ads->tcpbufused= ads->tcpbufdone= 0;
  ads->tcpbuf= 0;
  ads->flags= flags;
  ads->nservers= 0;

  readconfig(ads,"/etc/resolv.conf");
  readconfigenv(ads,"RES_CONF");
  readconfigenv(ads,"ADNS_RES_CONF");
  if (!ads->nservers) {
    if (ads->flags & adns_if_debug)
      fprintf(stderr,"adns: no nameservers, using localhost\n");
    addserver(ads,INADDR_LOOPBACK);
  }
  
  *ads_r= ads;
  return 0;
}

void query_fail(adns_state ads, adns_query qu, ands_status stat) {
  struct adns_answer ans;
  
  ans= qu->answer;
  if (!ans) ans= malloc(sizeof(*qu->answer));
  if (ans) {
    ans->status= stat;
    ans->cname= 0;
    ans->type= qu->type;
    ans->nrrs= 0;
  }
  qu->answer= ans;
  LIST_LINK_TAIL(ads.ready,qu);
}

void adns_event(adns_state ads,
		fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		int *maxfd, struct timeval *tv) {
  for (
}

int adns_submit(adns_state ads,
		const char *owner,
		adns_rrtype type,
		int flags,
		void *context,
		adns_query *query_r) {
  adns_query qu;
  adns_status stat;
  int ol, r;

  stat= 0;
  ol= strlen(owner);
  if (ol>MAXDNAME+1) { stat= ands_s_invaliddomain; ol= 0; }
  if (ol>0 && owner[ol-1]=='.') { flags &= ~adns_f_search; ol--; }
  qu= malloc(sizeof(*qu)+ol+1); if (!qu) return errno;
  qu->next= qu->back= qu->parent= qu->child= 0;
  qu->type= type;
  qu->answer= 0;
  qu->flags= flags;
  qu->context= context;
  qu->retries= 0;
  qu->server= 0;
  memcpy(qu->owner,owner,ol); qu->owner[ol]= 0;
  if (stat) {
    query_fail(ads,qu,stat);
  } else {
    LIST_LINK_TAIL(ads->input,qu);
    adns_event(ads,0,0,0,0,0);
  }
  *query_r= qu;
}
