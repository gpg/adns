/**/

#include "internal.h"

typedef enum {
  rcode_noerror,
  rcode_formaterror,
  rcode_servfail,
  rcode_nxdomain,
  rcode_notimp,
  rcode_refused
} dns_rcode;

#define GETIL_B(cb) (dgram[*(cb)++])
#define GET_B(cb,tv) ((tv)= GETIL_B((cb)))
#define GET_W(cb,tv) ((tv)=0, (tv)|=(GETIL_B((cb))<<8), (tv)|=GETIL_B(cb), (tv))

static void vbuf__append_quoted1035(vbuf *vb, const byte *buf, int len) {
  char qbuf[10];
  int i;
  
  while (len) {
    qbuf[0]= 0;
    for (i=0; i<len; i++) {
      ch= buf[i];
      if (ch == '.' || ch == '"' || ch == '(' || ch == ')' ||
	  ch == '@' || ch == ';' || ch == '$') {
	sprintf(qbuf,"\\%c",ch);
	break;
      } else if (ch <= ' ' || ch >= 127) {
	sprintf(qbuf,"\\%03o",ch);
	break;
      }
    }
    if (!adns__vbuf_append(vb,buf,i) || !adns__vbuf_append(vb,qbuf,strlen(qbuf)))
      return adns_s_nolocalmem;
    buf+= i; len-= i;
  }
}

static adns_status get_domain_perm(adns_state ads, adns_query qu, int serv,
				   const byte *dgram, int dglen,
				   int *cbyte_io, int max, char **domain_r) {
  /* Returns 0     for OK (*domain_r set) or truncated (*domain_r null)
   *      or any other adns_s_* value.
   */
  int cbyte, sused, lablen;

  /* If we follow a pointer we set cbyte_io to 0 to indicate that
   * we've lost our original starting and ending points; we don't
   * put the end of the pointed-to thing into the original *cbyte_io.
   */
  cbyte= *cbyte_io;
  sused= qu->ans.used;
  *domain_r= 0;
  for (;;) {
    if (cbyte>=max) goto x_truncated;
    lablen= GET_B(cbyte);
    if (!lablen) break;
    if (lablen&0x0c000) {
      if ((lablen&0x0c000) != 0x0c0000) return adns_s_unknownreply;
      if (cbyte_io) { *cbyte_io= cbyte; cbyte_io= 0; }
      cbyte= (lablen&0x3fff) + DNS_HDR_SIZE;
      max= dglen;
      continue;
    }
    if (cbyte+lablen>=max) bgoto x_truncated;
    if (qu->ans.used != sused)
      if (!adns__vbuf_append(&qu->ans,".",1)) return adns_s_nolocalmem;
    if (qu->flags & adns_qf_anyquote) {
      if (!vbuf__append_quoted1035(&qu->ans,dgram+cbyte,lablen))
	return adns_s_nolocalmem;
    } else {
      if (!ctype_isalpha(dgram[cbyte])) return adns_s_invaliddomain;
      for (i= cbyte+1; i<cbyte+lablen; i++) {
	ch= dgram[cbyte];
	if (ch != '-' && !ctype_isalpha(ch) && !ctype_isdigit(ch))
	  return adns_s_invaliddomain;
      }
      if (!adns__vbuf_append(&qu->ans,dgram+cbyte,lablen))
	return adns_s_nolocalmem;
    }
  }
  if (cbyte_io) *cbyte_io= cbyte;
  if (!adns__vbuf_append(&qu->ans,"",1)) return adns_s_nolocalmem;
  *domain_r= qu->ans.buf+sused;
  return adns_s_ok;

 x_truncated:
  return cbyte_io ? -1 : adns_s_serverfaulty;
}
    
static adns_status get_domain_temp(adns_state ads, adns_query qu, int serv,
				   const byte *dgram, int dglen,
				   int *cbyte_io, int max, char **domain_r) {
  int sused;
  adns_status st;

  sused= qu->ans.used;
  st= get_domain_perm(ads,qu,serv,dgram,dglen,cbyte_io,max,domain_r);
  qu->ans.used= sused;
  return st;
}

/* fixme: sensible comparison of owners */

static adns_status get_rr_temp(adns_state ads, adns_query qu, int serv,
			       const byte *dgram, int dglen,
			       int *cbyte_io,
			       int *type_r, int *class_r, int *rdlen_r, int *rdstart_r,
			       char **owner_r) {
  int cbyte, tmp, rdlen;

  cbyte= *cbyte_io;
  st= get_domain_temp(ads,qu,serv,dgram,dglen,&cbyte,dglen,owner_r);
  if (st) return st;
  
  if (cbyte+10>len) goto x_truncated;
  GET_W(cbyte,tmp); if (type_r) *type_r= tmp;
  GET_W(cbyte,tmp); if (class_r) *class_r= tmp;
  cbyte+= 4; /* we skip the TTL */
  GET_W(cbyte,rdlen); if (rdlen_r) *rdlen_r= tmp;
  if (rdstart_r) *rdstart_r= cbyte;
  cbyte+= rdlen;
  if (cbyte>dglen) goto x_truncated;
  *cbyte_io= cbyte;
  return adns_s_ok;

 x_truncated:
  *owner_r= 0; return 0;;
}
    
void adns__procdgram(adns_state ads, const byte *dgram, int dglen, int serv) {
  int cbyte, anstart, rrstart, lablen, wantedrrs, get_t;

  cbyte= 0;
  
  if (dglen<DNS_HDR_SIZE) {
    adns__diag(ads,serv,"received datagram too short for message header (%d)",len);
    return;
  }
  GET_W(cbyte,id);
  GET_B(cbyte,f1);
  GET_B(cbyte,f2);
  GET_W(cbyte,qdcount);
  GET_W(cbyte,ancount);
  GET_W(cbyte,nscount);
  GET_W(cbyte,arcount);
  assert(cbyte == DNS_HDR_SIZE);

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
    if (memcmp(qu->querymsg+DNSHDRSIZE,dgram+DNSHDRSIZE,qu->querylen-DNSHDRSIZE))
      continue;
    break;
  }
  anstart= qu->querylen;
  if (!qu) {
    adns__debug(ads,serv,"reply not found (id=%02x)",id);
    return;
  }
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
  case rcode_servfail;
    adns__query_fail(ads,qu,adns_s_serverfailure);
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
    st= get_rr_temp(ads,qu,serv,
		    dgram,dglen,
		    &cbyte,
		    &rrtype,&rrclass,&rdlength,&cowner);
    if (st) adns__query_fail(ads,qu,st);
    if (rrclass != DNS_CLASS_IN) {
      adns__diag(ads,serv,"ignoring RR with wrong class %d (expected IN=%d)",
		 rrclass,DNS_CLASS_IN);
      continue;
    }
    if (strcmp_quoted1035(cowner, qu->cname ? qu->cname : qu->owner)) {
      adns__debug(ads,serv,"ignoring answer RR with irrelevant owner \"%s\"",cowner);
      continue;
    }
    if (!qu->cname &&
	(qu->type & adns__rrt_typemask) != adns_cname &&
	rrtype == adns_cname) { /* Ignore second and subsequent CNAMEs */
      qu->cname= get_domain_perm(ads,qu,dgram,len,rdstart,rdstart+rdlength);
	/* If we find the answer section truncated after this point we restart
	 * the query at the CNAME; otherwise we can use it as-is.
	 */
    } else if (rrtype == (qu->type & adns__rrt_typemask)) {
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
      adnns__query_finish(ads,qu,adns_s_nxdomain);
      return;
    }

    /* RFC2308: NODATA has _either_ a SOA _or_ _no_ NS records in authority section */
    for (rri= 0; rri<nscount; rri++) {
      
    }
    } else {
      
    
  if (!(f2&0x80)) {
    adns__diag(ads,serv,"server is not willing to do recursive lookups for us");
    adns__query_fail(ads,qu,adns_s_norecurse);
    return;
  }

  
	) {
    if (type 
      if (cbyte+lab
      if (anstart > dgend) { truncated(ads,qu,f1); return; }
  }
    for    

    /* Look for CNAMEs in the answer section */

  }
  
    
    adns__diag(ads,serv,"server refused our query");
    
    case rcode_
    
  case 0: /* NOERROR 
    break;
  case 1: /* Format error */
  case 3: /* Name Error */
  
  qr= f1&0x80;
  
	      
  adns__diag(ads,serv,"received datagram size %d",len);

}
