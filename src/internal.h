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
#define UDPMAXDGRAM 512
#define NSPORT 53

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
  enum { query_udp, query_tcpwait, query_tcpsent, query_child, query_done } state;
  adns_query back, next;
  adns_query parent;
  struct { adns_query head, tail; } children;
  struct { adns_query back, next; } siblings;
  adns_rrtype type;
  adns_answer *answer;
  size_t ansalloc; ansused;
  int id, flags, udpretries;
  int nextudpserver;
  unsigned long sentudp, failedtcp; /* bitmap indexed by server */
  struct timeval timeout;
  void *context;
  unsigned char *querymsg;
  int querylen;
  char owner[1];
  /* After the owner name and nul comes the query message */

  /* Possible states:
   *
   *  state   Queue   child  id   answer    nextudpserver  sentudp     failedtcp
   *
   *  udp     NONE    null   >=0  null      0              zero        zero
   *  udp     timew   null   >=0  null      any            nonzero     zero
   *  udp     NONE    null   >=0  null      any            nonzero     zero
   *
   *  tcpwait timew   null   >=0  null      irrelevant     zero        any
   *  tcpsent timew   null   >=0  null      irrelevant     zero        any
   *
   *  child   childw  set    >=0  partial   irrelevant     irrelevant  irrelevant
   *  done    output  null   -1   set/null  irrelevant     irrelevant  irrelevant
   *
   *			      +------------------------+
   *             START -----> |      udp/NONE          |
   *			      +------------------------+
   *                         /                       |\  \
   *        too big for UDP /             UDP timeout  \  \ send via UDP
   *        do this ASAP!  /              more retries  \  \   do this ASAP!
   *                     |_                  desired     \  _|
   *		  +---------------+     	    	+-----------+
   *              | tcpwait/timew | ____                | udp/timew |
   *              +---------------+     \	    	+-----------+
   *                    |  ^             |                 | |
   *     TCP conn'd;    |  | TCP died    |                 | |
   *     send via TCP   |  | more        |     UDP timeout | |
   *     do this ASAP!  |  | servers     |      no more    | |
   *                    v  | to try      |      retries    | |
   *              +---------------+      |      desired    | |
   *              | tcpsent/timew | ____ |                 | |
   *    	  +---------------+     \|                 | |
   *                  \   \ TCP died     | TCP             | |
   *                   \   \ no more     | timeout         / |
   *                    \   \ servers    |                /  |
   *                     \   \ to try    |               /   |
   *                  got \   \          v             |_    / got
   *                 reply \   _| +------------------+      / reply
   *   	       	       	    \  	  | done/output FAIL |     /
   *                         \    +------------------+    /
   *                          \                          /
   *                           _|                      |_
   *                             (..... got reply ....)
   *                              /                   \
   *        need child query/ies /                     \ no child query
   *                            /                       \
   *                          |_                         _|
   *		    +--------------+		       +----------------+
   *                | child/childw | ----------------> | done/output OK |
   *                +--------------+  children done    +----------------+
   */
};

typedef struct {
  size_t used, avail;
  unsigned char *buf;
} adns__vbuf;

struct adns__state {
  /* FIXME: make sure this is all init'd properly */
  adns_initflags iflags;
  FILE *diagfile;
  struct { adns_query head, tail; } timew, childw, output;
  int nextid, udpsocket;
  adns_vbuf rqbuf, tcpsend, tcprecv;
  int nservers, tcpserver;
  enum adns__tcpstate { server_disconnected, server_connecting, server_ok } tcpstate;
  int tcpsocket;
  struct timeval tcptimeout;
  struct server {
    struct in_addr addr;
  } servers[MAXSERVERS];
};

/* From setup.c: */

void adns__vdiag(adns_state ads, adns_initflags prevent, const char *pfx,
		 int serv, const char *fmt, va_list al);
void adns__debug(adns_state ads, int serv, const char *fmt, ...) PRINTFFORMAT(3,4);
void adns__warn(adns_state ads, int serv, const char *fmt, ...) PRINTFFORMAT(3,4);
void adns__diag(adns_state ads, int serv, const char *fmt, ...) PRINTFFORMAT(3,4);

static inline int adns__vbuf_ensure(adns__vbuf *vb, size_t want);
int adns__vbuf_append(adns__vbuf *vb, const byte *data, size_t len);
int adns__vbuf_appendq(adns__vbuf *vb, const byte *data, size_t len);
/* 1=>success, 0=>realloc failed */

/* From submit.c: */

void adns__query_fail(adns_state ads, adns_query qu, adns_status stat);

/* From query.c: */

void adns__query_udp(adns_state ads, adns_query qu, struct timeval now);
void adns__query_tcp(adns_state ads, adns_query qu, struct timeval now);
adns_status adns__mkquery(adns_state ads, const char *owner, int ol, int id,
			  adns_rrtype type, adns_queryflags flags, int *qml_r);

/* From event.c: */
void adns__tcp_broken(adns_state ads, const char *what, const char *why);
void adns__tcp_tryconnect(adns_state ads);

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

static inline int ctype_whitespace(int c) { return c==' ' || c=='\n' || c=='\t'; }
static inline int ctype_digit(int c) { return c>='0' && c<='9'; }

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
