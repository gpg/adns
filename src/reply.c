/**/

#include "internal.h"

typedef enum {
  rcode_noerror,
  rcode_formaterror,
  rcode_serverfail,
  rcode_nxdomain,
  rcode_notimp,
  rcode_refused
} dns_rcode;

void adns__procdgram(adns_state ads, const byte *dgram, int len, int serv) {
  unsigned char *rpp;
  
  if (len<12) {
    adns__diag(ads,serv,"received datagram too short for message header (%d)",len);
    return;
  }
  id= GFREPLYW;
  f1= GFREPLYB;
  f2= GFREPLYB;
  qdcount= GFREPLYW;
  ancount= GFREPLYW;
  nscount= GFREPLYW;
  arcount= GFREPLYW;

  if (f1&0x80) {
    adns__diag(ads,serv,"server sent us a query, not a response");
    return;
  }
  if (f1&0x70) {
    adns__diag(ads,serv,"server sent us unknown opcode %d (wanted 0=QUERY)",
	       (f1>>4)&0x70);
    return;
  }
  if (!qdcount) {
    adns__diag(ads,serv,"server sent reply without quoting our question");
    return;
  } else if (qdcount>1) {
    adns__diag(ads,serv,"server claimed to answer %d questions with one message",
	       qdcount);
    return;
  }
  for (qu= ads->timew; qu= nqu; qu++) {
    nqu= qu->next;
    if (qu->id != id) continue;
    if (len < qu->querylen) continue;
    if (memcmp(qu->querymsg+12,rpp,qu->querylen-12)) continue;
    break;
  }
  if (!qu) {
    adns__debug(ads,serv,"reply not found (id=%02x)",id);
    return;
  }
  if (!(f2&0x80)) {
    adns__diag(ads,serv,"server is not willing to do recursive lookups for us");
    adns__query_fail(ads,qu,adns_s_norecurse);
    return;
  }
  if (!(f1&0x01)) {
    adns__diag(ads,serv,"server thinks we didn't ask for recursive lookup");
    adns__query_fail(ads,qu,adns_s_serverfaulty);
    return;
  }
  switch (f1&0x0f) {
  case 0: /* NOERROR */
    break;
  case 1: /* Format error */
    adns__diag(ads,serv,"server cannot understand our query (Format Error)");
    adns__query_fail(ads,qu,adns_s_serverfaulty);
    return;
  case 2: /* Server failure */
    adns__query_fail(ads,qu,adns_s_serverfailure);
    return;
  case 3: /* Name Error */
  
  qr= f1&0x80;
  
	      
  adns__diag(ads,serv,"received datagram size %d",len);

}
