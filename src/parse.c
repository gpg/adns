/**/

#include "internal.h"

int vbuf__append_quoted1035(vbuf *vb, const byte *buf, int len) {
  char qbuf[10];
  int i, ch;
  
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
      return 0;
    buf+= i; len-= i;
  }
  return 1;
}

adns_status adns__get_label(const byte *dgram, int dglen, int *max_io,
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
    cbyte= DNS_HDRSIZE+(lablen&0x3fff);
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

adns_status adns__get_domain_perm(adns_state ads, adns_query qu, int serv,
				  const byte *dgram, int dglen,
				  int *cbyte_io, int max, int *domainstart_r) {
  /* Returns 0     for OK (*domainstart_r >=0) or truncated (*domainstart_r == -1)
   *      or any other adns_s_* value.
   */
  int cbyte, sused, lablen, labstart, namelen, i, ch;
  adns_status st;

  /* If we follow a pointer we set cbyte_io to 0 to indicate that
   * we've lost our original starting and ending points; we don't
   * put the end of the pointed-to thing into the original *cbyte_io.
   */
  cbyte= *cbyte_io;
  sused= qu->ans.used;
  namelen= 0;
  for (;;) {
    st= adns__get_label(dgram,dglen,&max, &cbyte,&lablen,&labstart,&namelen);
    if (st) return st;
    if (lablen<0) goto x_truncated;
    if (!lablen) break;
    if (qu->ans.used != sused)
      if (!adns__vbuf_append(&qu->ans,".",1)) return adns_s_nolocalmem;
    if (qu->flags & adns_qf_anyquote) {
      if (!vbuf__append_quoted1035(&qu->ans,dgram+labstart,lablen))
	return adns_s_nolocalmem;
    } else {
      if (!ctype_alpha(dgram[labstart])) return adns_s_invaliddomain;
      for (i= cbyte+1; i<cbyte+lablen; i++) {
	ch= dgram[cbyte];
	if (ch != '-' && !ctype_alpha(ch) && !ctype_digit(ch))
	  return adns_s_invaliddomain;
      }
      if (!adns__vbuf_append(&qu->ans,dgram+labstart,lablen))
	return adns_s_nolocalmem;
    }
  }
  if (cbyte_io) *cbyte_io= cbyte;
  if (!adns__vbuf_append(&qu->ans,"",1)) return adns_s_nolocalmem;
  *domainstart_r= sused;
  return adns_s_ok;

 x_truncated:
  *domainstart_r= -1;
  return cbyte_io ? -1 : adns_s_serverfaulty;
}
    
adns_status adns__get_domain_temp(adns_state ads, adns_query qu, int serv,
				  const byte *dgram, int dglen,
				  int *cbyte_io, int max, int *domainstart_r) {
  int sused;
  adns_status st;

  sused= qu->ans.used;
  st= adns__get_domain_perm(ads,qu,serv,dgram,dglen,cbyte_io,max,domainstart_r);
  qu->ans.used= sused;
  return st;
}

adns_status adns__get_rr_temp(adns_state ads, adns_query qu, int serv,
			      const byte *dgram, int dglen, int *cbyte_io,
			      int *type_r, int *class_r, int *rdlen_r, int *rdstart_r,
			      const byte *eo_dgram, int eo_dglen, int eo_cbyte,
			      int *eo_matched_r) {
  /* _s_ok can have *type_r == -1 and other output invalid, for truncation
   * type_r and class_r must be !0, other _r may be 0.
   * eo_dgram==0 for no comparison, otherwise all eo_ must be valid.
   */
  int cbyte, tmp, rdlen, mismatch;
  int max, lablen, labstart, namelen, ch;
  int eo_max, eo_lablen, eo_labstart, eo_namelen, eo_ch;
  adns_status st;

  cbyte= *cbyte_io;
  mismatch= eo_dgram ? 1 : 0;

  namelen= 0; eo_namelen= 0;
  max= dglen; eo_max= eo_dglen;
  for (;;) {
    st= adns__get_label(dgram,dglen,&max,
			&cbyte,&lablen,&labstart,&namelen);
    if (st) return st;
    if (lablen<0) goto x_truncated;

    if (!mismatch) {
      st= adns__get_label(eo_dgram,eo_dglen,&eo_max,
			  &eo_cbyte,&eo_lablen,&eo_labstart,&eo_namelen);
      if (st) return st;
      assert(eo_lablen>=0);
      if (lablen != eo_lablen) mismatch= 1;
      while (!mismatch && lablen-- > 0) {
	ch= dgram[labstart++]; if (ctype_alpha(ch)) ch &= ~32;
	eo_ch= eo_dgram[eo_labstart++]; if (ctype_alpha(eo_ch)) eo_ch &= ~32;
	if (ch != eo_ch) mismatch= 1;
      }
    }
  }
  if (eo_matched_r) *eo_matched_r= !mismatch;
   
  if (cbyte+10>dglen) goto x_truncated;
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
