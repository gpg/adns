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

void adns__findlabel_start(findlabel_state *fls,
			   adns_state ads, int serv,
			   const byte *dgram, int dglen, int max,
			   int dmbegin, int *dmend_rlater) {
  fls->ads= ads;
  fls->serv= serv;
  fls->dgram= dgram;
  fls->dglen= dglen;
  fls->max= max;
  fls->cbyte= dmbegin;
  fls->namelen= 0;
  fls->dmend_r= dmend_rlater;
  fls->namelen_r= namelen_rlater;
}

adns_status adns__findlabel_next(findlabel_state fls,
				 int *lablen_r, int *labstart_r) {
  int lablen, jumped;

  jumped= 0;
  for (;;) {
    fls->cbyte += 2;
    if (fls->cbyte > fls->dglen) goto x_truncated;
    if (fls->cbyte > fls->max) goto x_serverfaulty;
    GET_W(fls->cbyte-2,lablen);
    if (!(lablen & 0x0c000)) break;
    if ((lablen & 0x0c000) != 0x0c000) return adns_s_unknownreply;
    if (jumped++) {
      adns__diag(ads,serv,"compressed datagram contains loop");
      return adns_s_serverfaulty;
    }
    if (fls->dmend_r) *(fls->dmend_r)= fls->cbyte;
    fls->cbyte= DNS_HDRSIZE+(lablen&0x3fff);
    fls->dmend_r= 0; fls->max= fls->dglen+1;
  }
  if (lablen) {
    if (fls->namelen) fls->namelen++;
    fls->namelen+= lablen;
    if (fls->namelen > DNS_MAXDOMAIN) return adns_s_domaintoolong;
    fls->cbyte+= lablen;
    if (fls->cbyte > fls->dglen) goto x_truncated;
    if (fls->cbyte > fls->max) goto x_serverfaulty;
  } else {
    if (fls->dmend_r) *(fls->dmend_r)= fls->cbyte;
    if (fls->namelen_r) *(fls->namelen_r)= fls->namelen;
  }
  if (labstart_r) *labstart_r= fls->cbyte;
  *lablen_r= lablen;
  return adns_s_ok;

 x_truncated:
  *lablen_r= -1;
  return adns_s_ok;

 x_serverfaulty: 
  adns__diag(ads,serv,"label in domain runs beyond end of domain");
  return adns_s_serverfaulty;
}

adns_status adns__parse_domain(adns_state ads, int serv, vbuf *vb,
			       const byte *dgram, int dglen,
			       int *cbyte_io, int max) {
  findlabel_state fls;
  
  int cbyte, lablen, labstart, namelen, i, ch;
  adns_status st;

  ands__findlabel_start(&fls,ads,serv, dgram,dglen,max, *cbyte_io,cbyte_io);
  vb->used= 0;
  for (;;) {
    st= adns__findlabel_next(&fls,&lablen,&labstart);
    if (st) return st;
    if (lablen<0) { vb->used=0; return adns_s_ok; }
    if (!lablen) break;
    if (vb->used)
      if (!adns__vbuf_append(&qu->ans,".",1)) return adns_s_nolocalmem;
    if (qu->flags & adns_qf_anyquote) {
      if (!vbuf__append_quoted1035(&qu->ans,dgram+labstart,lablen))
	return adns_s_nolocalmem;
    } else {
      if (!ctype_alpha(dgram[labstart])) return adns_s_invaliddomain;
      for (i= labstart+1; i<labstart+lablen; i++) {
	ch= dgram[i];
	if (ch != '-' && !ctype_alpha(ch) && !ctype_digit(ch))
	  return adns_s_invaliddomain;
      }
      if (!adns__vbuf_append(&qu->ans,dgram+labstart,lablen))
	return adns_s_nolocalmem;
    }
  }
  if (!adns__vbuf_append(&qu->ans,"",1)) return adns_s_nolocalmem;
  return adns_s_ok;
}
    
adns_status adns__findrr(adns_state ads, int serv,
			 const byte *dgram, int dglen, int *cbyte_io,
			 int *type_r, int *class_r, int *rdlen_r, int *rdstart_r,
			 const byte *eo_dgram, int eo_dglen, int eo_cbyte,
			 int *eo_matched_r) {
  /* Finds the extent and some of the contents of an RR in a datagram
   * and does some checks.  The datagram is *dgram, length dglen, and
   * the RR starts at *cbyte_io (which is updated afterwards to point
   * to the end of the RR).
   *
   * The type, class and RRdata length and start are returned iff
   * the corresponding pointer variables are not null.  type_r and
   * class_r may not be null.
   *
   * If the caller thinks they know what the owner of the RR ought to
   * be they can pass in details in eo_*: this is another (or perhaps
   * the same datagram), and a pointer to where the putative owner
   * starts in that datagram.  In this case *eo_matched_r will be set
   * to 1 if the datagram matched or 0 if it did not.  Either
   * both eo_dgram and eo_matched_r must both be non-null, or they
   * must both be null (in which case eo_dglen and eo_cbyte will be ignored).
   * The eo datagram and contained owner domain MUST be valid and
   * untruncated.
   *
   * If there is truncation then *type_r will be set to -1 and
   * *cbyte_io, *class_r, *rdlen_r, *rdstart_r and *eo_matched_r will be
   * undefined.
   *
   * If an error is returned then *type_r will be undefined too.
   */
  findlabel_state fls, eo_fls;
  int cbyte;
  
  int tmp, rdlen, mismatch;
  int max, lablen, labstart, namelen, ch;
  int eo_max, eo_lablen, eo_labstart, eo_namelen, eo_ch;
  adns_status st;

  cbyte= *cbyte_io;

  ands__findlabel_start(&fls,ads,serv, dgram,dglen,dglen,cbyte,&cbyte);
  if (eo_dgram) {
    ands__findlabel_start(&eo_fls,ads,serv, eo_dgram,eo_dglen,eo_dglen,eo_cbyte,0);
    mismatch= 0;
  } else {
    mismatch= 1;
  }
  
  for (;;) {
    st= adns__findlabel_next(&fls,&lablen,&labstart);
    if (st) return st;
    if (lablen<0) goto x_truncated;

    if (!mismatch) {
      st= adns__findlabel_next(&eo_fls,&eo_lablen,&eo_labstart);
      assert(!st); assert(eo_lablen>=0);
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
