/**/

#include "internal.h"

void adns__procdgram(adns_state ads, const byte *dgram, int len, int serv) {
  /* FIXME do something with incoming datagrams */
  adns__diag(ads,serv,"received datagram size %d",len);
}
