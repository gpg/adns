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

static adns_status get_label(const byte *dgram, int dglen, int *max_io,
			     int *cbyte_io, int *lablen_r, int *labstart_r,
			     int *namelen_io) {
  /* If succeeds, *lablen_r may be set to -1 to indicate truncation/overrun */
  int max, cbyte, lablen, namelen;

  max= *max_io;
  cbyte= *cbyte_io;
  
  for (;;) {
    if (cbyte+2 > max) goto x_truncated;
    GET_W(cbyte,lablen);
    if (!(lablen & 0x0c000)) break;
    if ((lablen & 0x0c000) != 0x0c000) return adns_s_unknownreply;
    if (cbyte_io) { *cbyte_io= cbyte; cbyte_io= 0; }
    cbyte= dgram+DNS_HDR_SIZE+(lablen&0x3fff);
    *max_io= max= dglen;
  }
  if (labstart_r) *labstart_r= cbyte;
  if (lablen) {
    namelen= *namelen_io;
    if (namelen) namelen++;
    namelen+= lablen;
    if (namelen > DNS_MAXDOMAIN) return adns_s_domaintoolong;
    *namelen_io= namelen;
    cbyte+= lablen;
    if (cbyte > max) goto x_truncated;
  }
  if (cbyte_io) *cbyte_io= cbyte;
  *lablen_r= lablen;
  return adns_s_ok;

 x_truncated:
  *lablen_r= -1;
  return adns_s_ok;
}

static adns_status get_domain_perm(adns_state ads, adns_query qu, int serv,
				   const byte *dgram, int dglen,
				   int *cbyte_io, int max, char **domain_r) {
  /* Returns 0     for OK (*domain_r set) or truncated (*domain_r null)
   *      or any other adns_s_* value.
   */
  int cbyte, sused, lablen, namelen;

  /* If we follow a pointer we set cbyte_io to 0 to indicate that
   * we've lost our original starting and ending points; we don't
   * put the end of the pointed-to thing into the original *cbyte_io.
   */
  cbyte= *cbyte_io;
  sused= qu->ans.used;
  *domain_r= 0;
  namelen= 0;
  for (;;) {
    st= get_label(dgram,dglen,&max, &cbyte,&lablen,&labstart,&namelen);
    if (st) return st;
    if (lablen<0) goto x_truncated;
    if (!lablen) break;
    if (qu->ans.used != sused)
      if (!adns__vbuf_append(&qu->ans,".",1)) return adns_s_nolocalmem;
    if (qu->flags & adns_qf_anyquote) {
      if (!vbuf__append_quoted1035(&qu->ans,dgram+labstart,lablen))
	return adns_s_nolocalmem;
    } else {
      if (!ctype_isalpha(dgram[labstart])) return adns_s_invaliddomain;
      for (i= cbyte+1; i<cbyte+lablen; i++) {
	ch= dgram[cbyte];
	if (ch != '-' && !ctype_isalpha(ch) && !ctype_isdigit(ch))
	  return adns_s_invaliddomain;
      }
      if (!adns__vbuf_append(&qu->ans,dgram+labstart,lablen))
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

static adns_status get_rr_temp(adns_state ads, adns_query qu, int serv,
			       const byte *dgram, int dglen, int *cbyte_io,
			       int *type_r, int *class_r, int *rdlen_r, int *rdstart_r,
			       const byte *eo_dgram, int eo_dglen, int eo_cbyte,
			       int *eo_matched_r) {
  /* _s_ok can have *type_r == -1 and other output invalid, for truncation
   * type_r and class_r must be !0, other _r may be 0.
   * eo_dgram==0 for no comparison, otherwise all eo_ must be valid.
   */
  int cbyte, tmp, rdlen, mismatch;
  int max, lablen, labstart, namelen;
  int eo_max, eo_lablen, eo_labstart, eo_namelen;

  cbyte= *cbyte_io;
  mismatch= eo_dgram ? 1 : 0;

  namelen= 0; eo_namelen= 0;
  max= dglen; eo_max= eo_dglen;
  for (;;) {
    st= get_label(dgram,dglen,&max,
		  &cbyte,&lablen,&labstart,&namelen);
    if (st) return st;
    if (lablen<0) goto x_truncated;

    if (!mismatch) {
      st= get_label(eo_dgram,eo_dglen,&eo_max,
		    &eo_cbyte,&eo_lablen,&eo_labstart,&eo_namelen);
      if (st) return st;
      assert(eo_lablen>=0);
      if (lablen != eo_lablen) mismatch= 1;
      while (!mismatch && lablen-- > 0) {
	ch= dgram[labstart++]; if (ctype_isalpha(ch)) ch &= ~32;
	eo_ch= eo_dgram[eo_labstart++]; if (ctype_isalpha(eo_ch)) eo_ch &= ~32;
	if (ch != eo_ch) mismatch= 1
      }
    }
  }
  if (eo_matched_r) *eo_matched_r= !mismatch;
  
  if (cbyte+10>len) goto x_truncated;
  GET_W(cbyte,tmp); *type_r= tmp;
  GET_W(cbyte,tmp); *class_r= tmp;
  cbyte+= 4; /* we skip the TTL */
  GET_W(cbyte,rdlen); if (rdlen_r) *rdlen_r= tmp;
  if (rdstart_r) *rdstart_r= cbyte;
  cbyte+= rdlen;
  if (cbyte>dglen) goto x_truncated;
  *cbyte_io= cbyte;
  return adns_s_ok;

 x_truncated:
  *type_r= -1;
  return 0;;
}
    
void adns__procdgram(adns_state ads, const byte *dgram, int dglen, int serv) {
  int cbyte, anstart, rrstart, lablen, wantedrrs, get_t, cnamestart;

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
    if (qu->cname) {
      st= get_rr_temp(ads,qu,serv, dgram,dglen,&cbyte,
		      &rrtype,&rrclass,&rdlength,&rdstart,
		      dgram,dglen,cnamestart, &ownermatched);
    } else {
      st= get_rr_temp(ads,qu,serv, dgram,dglen,&cbyte,
		      &rrtype,&rrclass,&rdlength,&rdstart,
		      qu->querymsg,qu->querylen,DNS_HDR_SIZE, &ownermatched);
    }
    if (st) adns__query_fail(ads,qu,st);
    if (rrtype == -1) goto x_truncated;

    if (rrclass != DNS_CLASS_IN) {
      adns__diag(ads,serv,"ignoring answer RR with wrong class %d (expected IN=%d)",
		 rrclass,DNS_CLASS_IN);
      continue;
    }
    if (!ownermatched) {
      if (ads->iflag & adns_if_debug) {
	st= get_domain_temp(ads,qu,serv, dgram,dglen,&rrstart,dglen, &cowner);
	if (st) adns__debug(ads,serv,"ignoring RR with an irrelevant owner, code %d",st);
	else adns__debug(ads,serv,"ignoring RR with an irrelevant owner \"%s\"",cowner);
      }
      continue;
    }
    if (!qu->cname &&
	(qu->type & adns__rrt_typemask) != adns_cname &&
	rrtype == adns_cname) { /* Ignore second and subsequent CNAMEs */
      st= get_domain_perm(ads,qu,serv, dgram,dglen,
			  &rdstart,rdstart+rdlength,&qu->cname);
      if (st) return st;
      if (!qu->cname) goto x_truncated;
      /* If we find the answer section truncated after this point we restart
       * the query at the CNAME; if beforehand then we obviously have to use
       * TCP.  If there is no truncation we can use the whole answer if
       * it contains the relevant info.
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
      adns__query_finish(ads,qu,adns_s_nxdomain);
      return;
    }

    /* RFC2308: NODATA has _either_ a SOA _or_ _no_ NS records in authority section */
    foundsoa= 0; foundns= 0;
    for (rri= 0; rri<nscount; rri++) {
      rrstart= cbyte;
      st= get_rr_temp(ads,qu,serv, dgram,dglen,&cbyte,
		      &rrtype,&rrclass, &rdlength,&rdstart, 0,0,0,0);
      if (st) return st;
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
    if (qu->cname) {
      cname_recurse(ads,qu);
      return;
    }

    /* Bloody hell, I thought we asked for recursion ? */
    if (!flg_ra) {
      adns__diag(ads,serv,"server is not willing to do recursive lookups for us");
      adns__query_fail(ads,qu,adns_s_norecurse);
      return;
    }
    adns__diag(ads,serv,"server claims to do recursion, but gave us a referral");
    adns__query_fail(ads,qu,adns_s_serverfault);
    return;
  }

  /* Now, we have some RRs which we wanted. */
  rrs= 
    
    }
    } else {
      
{ truncated(ads,qu,flg_ra); return; }    
  
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

  while (
  switch (type) {
  case adns_r_a:  
  adns_r_a_mf=                  adns_r_a|adns__qtf_masterfmt,
  
  adns_r_ns_raw=             2,
  adns_r_ns=                    adns_r_ns_raw|adns__qtf_deref,
  adns_r_ns_mf=                 adns_r_ns_raw|adns__qtf_masterfmt,
  
  adns_r_cname=              5,
  adns_r_cname_mf=              adns_r_cname|adns__qtf_masterfmt,
  
  adns_r_soa_raw=            6,
  adns_r_soa=                   adns_r_soa_raw|adns__qtf_mail822, 
  adns_r_soa_mf=                adns_r_soa_raw|adns__qtf_masterfmt,
  
  adns_r_null=              10,
  adns_r_null_mf=               adns_r_null|adns__qtf_masterfmt,
  
  adns_r_ptr_raw=           12,
  adns_r_ptr=                   adns_r_ptr_raw|adns__qtf_deref,
  adns_r_ptr_mf=                adns_r_ptr_raw|adns__qtf_masterfmt,
  
  adns_r_hinfo=             13,  
  adns_r_hinfo_mf=              adns_r_hinfo|adns__qtf_masterfmt,
  
  adns_r_mx_raw=            15,
  adns_r_mx=                    adns_r_mx_raw|adns__qtf_deref,
  adns_r_mx_mf=                 adns_r_mx_raw|adns__qtf_masterfmt,
  
  adns_r_txt=               16,
  adns_r_txt_mf=                adns_r_txt|adns__qtf_masterfmt,
  
  adns_r_rp_raw=            17,
  adns_r_rp=                    adns_r_rp_raw|adns__qtf_mail822,
  adns_r_rp_mf=                 adns_r_rp_raw|adns__qtf_masterfmt
    
  
