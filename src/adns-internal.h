/**/

#ifndef ADNS_INTERNAL_H_INCLUDED
#define ADNS_INTERNAL_H_INCLUDED

#include <sys/time.h>

#include "adns.h"

#define MAXSERVERS 5
#define MAXUDPRETRIES 10
#define UDPRETRYMS 2000
#define TCPMS 20000

struct adns__query {
  adns_query next, back;
  adns_query parent, child;
  adns_rrtype type;
  adns_answer *answer;
  int id, flags, udpretries, nextserver;
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

struct adns__state {
  adns_initflags iflags;
  struct { adns_query head, tail; } tosend, timew, childw, output;
  int nextid, udpsocket;
  int qbufavail, tcpbufavail, tcpbufused, tcpbufdone;
  unsigned char *qbuf, *tcpbuf;
  int nservers;
  struct server {
    struct in_addr addr;
    enum { server_disc, server_connecting, server_ok } state;
    int tcpsocket;
    struct timeval timeout;
    struct { adns_query head, tail; } connw;
  } servers[MAXSERVERS];
};

#endif
