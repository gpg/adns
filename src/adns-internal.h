/**/

#ifndef ADNS_INTERNAL_H_INCLUDED
#define ADNS_INTERNAL_H_INCLUDED

#include <sys/time.h>

#include "adns.h"

/* Configuration and constants */

#define MAXSERVERS 5
#define MAXUDPRETRIES 15
#define UDPRETRYMS 2000
#define TCPMS 30000
#define LOCALRESOURCEMS 20

/* Shared data structures */

union adns__align {
  adns_status status;
  char *cp;
  adns_rrtype type;
  int int;
  struct in_addr ia;
  unsigned long ul;
};

struct adns__query {
  /* FIXME: make sure this is all init'd properly */
  adns_query back, next;
  adns_query parent;
  struct { adns_query head, tail; } children;
  struct { adns_query back, next; } siblings;
  adns_rrtype type;
  adns_answer *answer;
  size_t ansalloc; ansused;
  int id, flags, udpretries; /* udpretries==-1 => _f_usevc or too big for UDP */
  int nextudpserver;
  unsigned long sentudp, senttcp; /* bitmaps indexed by server */
  struct timeval timeout;
  void *context;
  unsigned char *querymsg;
  int querylen;
  char owner[1];
  /* Possible states:
   *  Queue   child  id   answer    nextserver  sentudp             senttcp
   *  tosend  null   >=0  null      any         any                 any
   *  timew   null   >=0  null      any         at least 1 bit set  any
   *  childw  set    >=0  partial   any         any                 any
   *  output  null   -1   set/null  any         any                 any
   */
};

struct adns__vbuf {
  size_t used, avail;
  unsigned char *buf;
};

struct adns__state {
  /* FIXME: make sure this is all init'd properly */
  adns_initflags iflags;
  struct { adns_query head, tail; } tosend, timew, childw, output;
  int nextid, udpsocket;
  adns_vbuf rqbuf, tcpsend, tcprecv;
  int nservers, tcpserver;
  enum adns__tcpstate { server_disc, server_connecting, server_ok } tcpstate;
  int tcpsocket;
  struct timeval tcptimeout;
  struct server {
    struct in_addr addr;
  } servers[MAXSERVERS];
};

/* From setup.c: */

void adns__debug(adns_state ads, const char *fmt, ...) PRINTFFORMAT(2,3);
void adns__diag(adns_state ads, const char *fmt, ...) PRINTFFORMAT(2,3);

/* From submit.c: */

void adns__query_fail(adns_state ads, adns_query qu, adns_status stat);

/* From query.c: */

void adns__quproc_tosend(adns_state ads, adns_query qu, struct timeval now) {

/* Useful static inline functions: */

static inline void timevaladd(struct timeval *tv_io, long ms) {
  struct timeval tmp;
  assert(ms>=0);
  tmp= *tv_io;
  tmp.tv_usec += (ms%1000)*1000;
  tmp.tv_sec += ms/1000;
  if (tmp.tv_usec >= 1000) { tmp.tv_sec++; tmp.tv_usec -= 1000; }
  *tv_io= tmp;
}    

/* Useful macros */

#define LIST_UNLINK_PART(list,node,part) \
  do { \
    if ((node)->back) (node)->back->part next= (node)->part next; \
      else                        (list).head= (node)->part next; \
    if ((node)->next) (node)->next->part back= (node)->part back; \
      else                        (list).tail= (node)->part back; \
  } while(0)

#define LIST_LINK_TAIL_PART(list,node,part) \
  do { \
    (node)->part back= 0; \
    (node)->part next= (list).tail; \
    if ((list).tail) (list).tail->part back= (node); else (list).part head= (node); \
    (list).tail= (node); \
  } while(0)

#define LIST_UNLINK(list,node) LIST_UNLINK_PART(list,node,)
#define LIST_LINK_TAIL_PART(list,node) LIST_LINK_TAIL(list,node,)

#endif
