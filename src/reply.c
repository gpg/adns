/**/

#include "internal.h"

static void cname_recurse(adns_state ads, adns_query qu, adns_queryflags xflags) {
  abort(); /* FIXME */
}
    
void adns__procdgram(adns_state ads, const byte *dgram, int dglen,
		     int serv, struct timeval now) {
  int cbyte, rrstart, wantedrrs, rri, foundsoa, foundns;
  int id, f1, f2, qdcount, ancount, nscount, arcount, flg_ra, flg_tc;
  int rrtype, rrclass, rdlength, rdstart, ownermatched, ownerstart;
  int anstart, nsstart, arstart;
  int currentrrs;
  adns_query qu, nqu;
  dns_rcode rcode;
  adns_status st;
= 0;
  
  if (dglen<DNS_HDRSIZE) {
    adns__diag(ads,serv,"received datagram too short for message header (%d)",dglen);
    return;
  }
  GET_W(cbyte,id);
  GET_B(cbyte,f1);
  GET_B(cbyte,f2);
  GET_W(cbyte,qdcount);
  GET_W(cbyte,ancount);
  GET_W(cbyte,nscount);
  GET_W(cbyte,arcount);
  assert(cbyte == DNS_HDRSIZE);

  flg_tc= f1&0x20;
  flg_ra= f2&0x80;

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
  for (qu= ads->timew.head; qu; qu= nqu) {
    nqu= qu->next;
    if (qu->id != id) continue;
    if (dglen < qu->querylen) continue;
    if (memcmp(qu->querymsg+DNS_HDRSIZE,dgram+DNS_HDRSIZE,qu->querylen-DNS_HDRSIZE))
      continue;
    break;
  }
  assert(qu->cnameoff == -1);
  anstart= qu->querylen;
  if (!qu) {
    adns__debug(ads,serv,"reply not found (id=%02x)",id);
    return;
  }

  LIST_UNLINK(ads->timew,qu);
  /* We're definitely going to do something with this query now */
  
  if (!(f1&0x01)) {
    adns__diag(ads,serv,"server thinks we didn't ask for recursive lookup");
    adns__query_fail(ads,qu,adns_s_serverfaulty);
    return;
  }

  rcode= (f1&0x0f);
  switch (rcode) {
  case rcode_noerror:
  case rcode_nxdomain:
    break;
  case rcode_formaterror:
    adns__warn(ads,serv,"server cannot understand our query (Format Error)");
    adns__query_fail(ads,qu,adns_s_serverfaulty);
    return;
  case rcode_servfail:
    adns__query_fail(ads,qu,adns_s_servfail);
    return;
  case rcode_notimp:
    adns__warn(ads,serv,"server claims not to implement our query");
    adns__query_fail(ads,qu,adns_s_notimplemented);
    return;
  case rcode_refused:
    adns__warn(ads,serv,"server refused our query");
    adns__query_fail(ads,qu,adns_s_refused);
    return;
  default:
    adns__warn(ads,serv,"server gave unknown response code %d",rcode);
    adns__query_fail(ads,qu,adns_s_reasonunknown);
    return;
  }

  /* Now, take a look at the answer section, and see if it is complete.
   * If it has any CNAMEs we stuff them in the answer.
   */
  wantedrrs= 0;
  for (rri= 0; rri<ancount; rri++) {
    rrstart= cbyte;
    if (qu->cnameoff >= 0) {
      st= adns__findrr(ads,serv, dgram,dglen,&cbyte,
		       &rrtype,&rrclass,&rdlength,&rdstart,
		       dgram,dglen,qu->cnameoff, &ownermatched);
    } else {
      st= adns__get_rr_temp(ads,qu,serv, dgram,dglen,&cbyte,
			    &rrtype,&rrclass,&rdlength,&rdstart,
			    qu->querymsg,qu->querylen,DNS_HDRSIZE, &ownermatched);
    }
    if (st) adns__query_fail(ads,qu,st);
    if (rrtype == -1) goto x_truncated;

    if (rrclass != DNS_CLASS_IN) {
      adns__diag(ads,serv,"ignoring answer RR with wrong class %d (expected IN=%d)",
		 rrclass,DNS_CLASS_IN);
      continue;
    }
    if (!ownermatched) {
      if (ads->iflags & adns_if_debug) {
	st= adns__get_domain_temp(ads,qu,serv, dgram,dglen,&rrstart,dglen, &ownerstart);
	if (st)
	  adns__debug(ads,serv, "ignoring RR with an irrelevant owner"
		      " whose format is bad, code %d",st);
	else if (ownerstart>=0)
	  adns__debug(ads,serv, "ignoring RR with an irrelevant owner"
		      " \"%s\"", qu->ans.buf+ownerstart);
	else
	  adns__debug(ads,serv,"ignoring RR with an irrelevant truncated owner");
      }
      continue;
    }
    if (qu->cnameoff<0 &&
	(qu->typei->type & adns__rrt_typemask) != adns_r_cname &&
	rrtype == adns_r_cname) { /* Ignore second and subsequent CNAMEs */
      st= adns__get_domain_perm(ads,qu,serv, dgram,dglen,
				&rdstart,rdstart+rdlength,&qu->cnameoff);
      if (st) { adns__query_fail(ads,qu,st); return; }
      if (qu->cnameoff==-1) goto x_truncated;
      /* If we find the answer section truncated after this point we restart
       * the query at the CNAME; if beforehand then we obviously have to use
       * TCP.  If there is no truncation we can use the whole answer if
       * it contains the relevant info.
       */
    } else if (rrtype == (qu->typei->type & adns__rrt_typemask)) {
      wantedrrs++;
    } else {
      adns__debug(ads,serv,"ignoring answer RR with irrelevant type %d",rrtype);
    }
  }

  /* If we got here then the answer section is intact. */
  nsstart= cbyte;

  if (!wantedrrs) {
    /* Oops, NODATA or NXDOMAIN or perhaps a referral (which would be a problem) */
    
    if (rcode == rcode_nxdomain) {
      adns__query_finish(ads,qu,adns_s_nxdomain);
      return;
    }

    /* RFC2308: NODATA has _either_ a SOA _or_ _no_ NS records in authority section */
    foundsoa= 0; foundns= 0;
    for (rri= 0; rri<nscount; rri++) {
      rrstart= cbyte;
      st= adns__get_rr_temp(ads,qu,serv, dgram,dglen,&cbyte,
			    &rrtype,&rrclass, &rdlength,&rdstart, 0,0,0,0);
      if (st) { adns__query_fail(ads,qu,st); return; }
      if (rrtype==-1) goto x_truncated;
      if (rrclass != DNS_CLASS_IN) {
	adns__diag(ads,serv,"ignoring authority RR with wrong class %d (expected IN=%d)",
		   rrclass,DNS_CLASS_IN);
	continue;
      }
      if (rrtype == adns_r_soa_raw) { foundsoa= 1; break; }
      else if (rrtype == adns_r_ns_raw) { foundns= 1; }
    }

    if (foundsoa || !foundns) {
      /* Aha !  A NODATA response, good. */
      adns__query_finish(ads,qu,adns_s_nodata);
      return;
    }

    /* Now what ?  No relevant answers, no SOA, and at least some NS's.
     * Looks like a referral.  Just one last chance ... if we came across
     * a CNAME then perhaps we should do our own CNAME lookup.
     */
    if (qu->cnameoff != -1) { cname_recurse(ads,qu,0); return; }

    /* Bloody hell, I thought we asked for recursion ? */
    if (!flg_ra) {
      adns__diag(ads,serv,"server is not willing to do recursive lookups for us");
      adns__query_fail(ads,qu,adns_s_norecurse);
      return;
    }
    adns__diag(ads,serv,"server claims to do recursion, but gave us a referral");
    adns__query_fail(ads,qu,adns_s_serverfaulty);
    return;
  }

  /* Now, we have some RRs which we wanted. */

  qu->rrsoff= adns__vbuf_malloc(&qu->ans,qu->typei->rrsz*wantedrrs);
  if (qu->rrsoff == -1) adns__query_fail(ads,qu,adns_s_nolocalmem);

  cbyte= anstart;
  currentrrs= 0;
  arstart= -1;
  for (rri=0; rri<ancount; rri++) {
    st= adns__get_rr_temp(ads,qu,serv, dgram,dglen,&cbyte,
			  &rrtype,&rrclass, &rdlength,&rdstart, 0,0,0,0);
    assert(!st); assert(rrtype != -1);
    if (rrclass != DNS_CLASS_IN ||
	rrtype != (qu->typei->type & adns__rrt_typemask))
      continue;
    assert(currentrrs<wantedrrs);
    st= qu->typei->get_fn(ads,qu,serv, dgram,dglen, &rdstart,rdstart+rdlength,
			  nsstart,arcount,&arstart, qu->rrsoff,&currentrrs);
    if (st) { adns__query_fail(ads,qu,st); return; }
    if (currentrrs==-1) goto x_truncated;
  }

  /* This may have generated some child queries ... */
  if (qu->children.head) {
    qu->state= query_child;
    LIST_LINK_TAIL(ads->childw,qu);
    return;
  }

  adns__query_finish(ads,qu,adns_s_ok);
  return;

x_truncated:
  if (!flg_tc) {
    adns__diag(ads,serv,"server sent datagram which points outside itself");
    adns__query_fail(ads,qu,adns_s_serverfaulty);
    return;
  }
  if (qu->cnameoff != -1) { cname_recurse(ads,qu,adns_qf_usevc); return; }
  qu->cnameoff= -1;
  qu->rrsoff= -1;
  ans= (adns_answer*)qu->ans.buf;
  ans->nrrs= 0;
  qu->ans.used= sizeof(adns_answer);
  qu->flags |= adns_qf_usevc;
  adns__query_udp(ads,qu,now);
}
