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
  struct adns_answer *answer;
  int flags, udpretries, server;
  struct timeval timeout;
  void *context;
  char owner[1];
};

struct adns__state {
  adns_initflags iflags;
  struct { adns_query head, tail; } input, timew, childw, output;
  int udpsocket;
  int qbufavail, tcpbufavail, tcpbufused, tcpbufdone;
  char *qbuf, *tcpbuf;
  int nservers;
  struct {
    struct in_addr addr;
    int tcpsocket;
    struct timeval timeout;
    struct { adns_query head, tail; } connw;
  } servers[MAXSERVERS];
};

#endif
