/*
 * types.c
 * - RR-type-specific code, and the machinery to call it
 */
/*
 *  This file is part of adns, which is Copyright (C) 1997, 1998 Ian Jackson
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA. 
 */

#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "internal.h"

#define R_NOMEM           return adns_s_nolocalmem
#define CSP_ADDSTR(s)     if (!adns__vbuf_appendstr(vb,(s))) R_NOMEM; else;

static int dip_inaddr(struct in_addr a, struct in_addr b) {
  /* fixme implement sortlist */
  return 0;
}

static adns_status pa_inaddr(const parseinfo *pai, int cbyte, int max, void *datap) {
  struct in_addr *storeto= datap;
  
  if (max-cbyte != 4) return adns_s_invaliddata;
  memcpy(storeto, pai->dgram + cbyte, 4);
  return adns_s_ok;
}

static int di_inaddr(const void *datap_a, const void *datap_b) {
  const struct in_addr *ap= datap_a, *bp= datap_b;

  return dip_inaddr(*ap,*bp);
}

static adns_status cs_inaddr(vbuf *vb, const void *datap) {
  const struct in_addr *rrp= datap, rr= *rrp;
  const char *ia;

  ia= inet_ntoa(rr); assert(ia);
  CSP_ADDSTR(ia);
  return adns_s_ok;
}

static adns_status pa_addr(const parseinfo *pai, int cbyte, int max, void *datap) {
  adns_addr *storeto= datap;
  const byte *dgram= pai->dgram;

  if (max-cbyte != 4) return adns_s_invaliddata;
  storeto->len= sizeof(storeto->addr.inet);
  memset(&storeto->addr,0,sizeof(storeto->addr.inet));
  storeto->addr.inet.sin_family= AF_INET;
  storeto->addr.inet.sin_port= 0;
  memcpy(&storeto->addr.inet.sin_addr,dgram+cbyte,4);
  return adns_s_ok;
}

static int di_addr(const void *datap_a, const void *datap_b) {
  const adns_addr *ap= datap_a, *bp= datap_b;

  assert(ap->addr.sa.sa_family == AF_INET);
  return dip_inaddr(ap->addr.inet.sin_addr,bp->addr.inet.sin_addr);
}

static adns_status csp_addr(vbuf *vb, const adns_addr *rrp) {
  const char *ia;
  static char buf[30];

  switch (rrp->addr.inet.sin_family) {
  case AF_INET:
    CSP_ADDSTR("AF_INET ");
    ia= inet_ntoa(rrp->addr.inet.sin_addr); assert(ia);
    CSP_ADDSTR(ia);
    break;
  default:
    sprintf(buf,"AF=%u",rrp->addr.sa.sa_family);
    CSP_ADDSTR(buf);
    break;
  }
  return adns_s_ok;
}

static adns_status cs_addr(vbuf *vb, const void *datap) {
  const adns_addr *rrp= datap;

  return csp_addr(vb,rrp);
}

static adns_status pap_domain(const parseinfo *pai, int *cbyte_io, int max,
			      char **domain_r, parsedomain_flags flags) {
  adns_status st;
  char *dm;
  
  st= adns__parse_domain(pai->qu->ads, pai->serv, pai->qu, &pai->qu->vb, flags,
			 pai->dgram,pai->dglen, cbyte_io, max);
  if (st) return st;
  if (!pai->qu->vb.used) return adns_s_invaliddata;

  dm= adns__alloc_interim(pai->qu, pai->qu->vb.used+1);
  if (!dm) R_NOMEM;

  dm[pai->qu->vb.used]= 0;
  memcpy(dm,pai->qu->vb.buf,pai->qu->vb.used);
  
  *domain_r= dm;
  return adns_s_ok;
}

static adns_status pa_host_raw(const parseinfo *pai, int cbyte, int max, void *datap) {
  char **rrp= datap;
  adns_status st;

  st= pap_domain(pai, &cbyte, max, rrp,
		 pai->qu->flags & adns_qf_quoteok_anshost ? pdf_quoteok : 0);
  if (st) return st;
  
  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}

static adns_status pa_mx_raw(const parseinfo *pai, int cbyte, int max, void *datap) {
  const byte *dgram= pai->dgram;
  adns_rr_intstr *rrp= datap;
  adns_status st;
  int pref;

  if (cbyte+2 > max) return adns_s_invaliddata;
  GET_W(cbyte,pref);
  rrp->i= pref;
  st= pap_domain(pai, &cbyte, max, &rrp->str,
		 pai->qu->flags & adns_qf_quoteok_anshost ? pdf_quoteok : 0);
  if (st) return st;
  
  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}


static adns_status pap_findaddrs(const parseinfo *pai, adns_rr_hostaddr *ha,
				 int *cbyte_io, int count, int dmstart) {
  int rri, naddrs;
  int type, class, rdlen, rdstart, ownermatched;
  adns_status st;
  
  for (rri=0, naddrs=-1; rri<count; rri++) {
    st= adns__findrr_anychk(pai->qu, pai->serv, pai->dgram, pai->dglen, cbyte_io,
			    &type, &class, &rdlen, &rdstart,
			    pai->dgram, pai->dglen, dmstart, &ownermatched);
    if (st) return st;
    if (!ownermatched || class != DNS_CLASS_IN || type != adns_r_a) {
      if (naddrs>0) break; else continue;
    }
    if (naddrs == -1) {
      naddrs= 0;
    }
    if (!adns__vbuf_ensure(&pai->qu->vb, (naddrs+1)*sizeof(adns_addr))) R_NOMEM;
    st= pa_addr(pai, rdstart,rdstart+rdlen, pai->qu->vb.buf + naddrs*sizeof(adns_addr));
    if (st) return st;
    naddrs++;
  }
  if (naddrs >= 0) {
    ha->addrs= adns__alloc_interim(pai->qu, naddrs*sizeof(adns_addr));
    if (!ha->addrs) R_NOMEM;
    memcpy(ha->addrs, pai->qu->vb.buf, naddrs*sizeof(adns_addr));
    ha->naddrs= naddrs;
    ha->astatus= adns_s_ok;

    adns__isort(ha->addrs, naddrs, sizeof(adns_addr), pai->qu->vb.buf, di_addr);
  }
  return adns_s_ok;
}

static adns_status pap_hostaddr(const parseinfo *pai, int *cbyte_io,
				int max, adns_rr_hostaddr *rrp) {
  adns_status st;
  int dmstart, cbyte;

  dmstart= cbyte= *cbyte_io;
  st= pap_domain(pai, &cbyte, max, &rrp->host,
		 pai->qu->flags & adns_qf_quoteok_anshost ? pdf_quoteok : 0);
  if (st) return st;
  *cbyte_io= cbyte;

  rrp->astatus= adns_s_ok;
  rrp->naddrs= -1;
  rrp->addrs= 0;

  cbyte= pai->nsstart;

  st= pap_findaddrs(pai, rrp, &cbyte, pai->nscount, dmstart);
  if (st) return st;
  if (rrp->naddrs != -1) return adns_s_ok;

  st= pap_findaddrs(pai, rrp, &cbyte, pai->arcount, dmstart);
  if (st) return st;
  if (rrp->naddrs != -1) return adns_s_ok;

  rrp->naddrs= 0; /* fixme additional section didn't have required data */
  rrp->astatus= adns_s_notimplemented;

  return adns_s_ok;
}

static adns_status pa_hostaddr(const parseinfo *pai, int cbyte, int max, void *datap) {
  adns_rr_hostaddr *rrp= datap;
  adns_status st;

  st= pap_hostaddr(pai, &cbyte, max, rrp);
  if (st) return st;
  if (cbyte != max) return adns_s_invaliddata;

  return adns_s_ok;
}

static adns_status pa_mx(const parseinfo *pai, int cbyte, int max, void *datap) {
  const byte *dgram= pai->dgram;
  adns_rr_inthostaddr *rrp= datap;
  adns_status st;
  int pref;

  if (cbyte+2 > max) return adns_s_invaliddata;
  GET_W(cbyte,pref);
  rrp->i= pref;
  st= pap_hostaddr(pai, &cbyte, max, &rrp->ha);
  if (st) return st;
  
  if (cbyte != max) return adns_s_invaliddata;
  return adns_s_ok;
}

static int dip_hostaddr(const adns_rr_hostaddr *ap, const adns_rr_hostaddr *bp) {
  if (ap->astatus != bp->astatus) return ap->astatus;
  if (ap->astatus) return 0;

  assert(ap->addrs[0].addr.sa.sa_family == AF_INET);
  assert(bp->addrs[0].addr.sa.sa_family == AF_INET);
  return dip_inaddr(ap->addrs[0].addr.inet.sin_addr, bp->addrs[0].addr.inet.sin_addr);
}

static int di_hostaddr(const void *datap_a, const void *datap_b) {
  const adns_rr_hostaddr *ap= datap_a, *bp= datap_b;

  return dip_hostaddr(ap,bp);
}

static int di_mx_raw(const void *datap_a, const void *datap_b) {
  const adns_rr_intstr *ap= datap_a, *bp= datap_b;

  if (ap->i < bp->i) return 0;
  if (ap->i > bp->i) return 1;
  return 0;
}

static int di_mx(const void *datap_a, const void *datap_b) {
  const adns_rr_inthostaddr *ap= datap_a, *bp= datap_b;

  if (ap->i < bp->i) return 0;
  if (ap->i > bp->i) return 1;
  return dip_hostaddr(&ap->ha,&bp->ha);
}

static adns_status pa_txt(const parseinfo *pai, int cbyte, int max, void *datap) {
  adns_rr_intstr **rrp= datap, *table, *te;
  const byte *dgram= pai->dgram;
  int ti, tc, l, startbyte;

  startbyte= cbyte;
  if (cbyte >= max) return adns_s_invaliddata;
  tc= 0;
  while (cbyte < max) {
    GET_B(cbyte,l);
    cbyte+= l;
  }
  if (cbyte != max) return adns_s_invaliddata;

  table= adns__alloc_interim(pai->qu,sizeof(*table)*(tc+1));
  if (!table) R_NOMEM;

  for (cbyte=startbyte, ti=0, te=table; ti<tc; ti++, te++) {
    GET_B(cbyte,l);
    te->str= adns__alloc_interim(pai->qu, l+1);
    if (!te->str) R_NOMEM;
    te->str[l]= 0;
    memcpy(te->str,dgram+cbyte,l);
    te->i= l;
  }
  assert(cbyte == max);

  te->i= -1;
  te->str= 0;
  
  *rrp= table;
  return adns_s_ok;
}

static adns_status csp_textdata(vbuf *vb, const char *dp, int len) {
  unsigned char ch;
  char buf[10];
  int cn;

  CSP_ADDSTR("\"");
  for (cn=0; cn<len; cn++) {
    ch= *dp++;
    if (ch >= 32 && ch <= 126 && ch != '"' && ch != '\\') {
      if (!adns__vbuf_append(vb,&ch,1)) R_NOMEM;
    } else {
      sprintf(buf,"\\%02x",ch);
      CSP_ADDSTR(buf);
    }
  }
  CSP_ADDSTR("\"");
  
  return adns_s_ok;
}

static adns_status csp_qstring(vbuf *vb, const char *dp) {
  return csp_textdata(vb, dp, strlen(dp));
}

static adns_status cs_str(vbuf *vb, const void *datap) {
  const char *const *rrp= datap;

  return csp_qstring(vb,*rrp);
}

static adns_status cs_intstr(vbuf *vb, const void *datap) {
  const adns_rr_intstr *rrp= datap;
  char buf[10];

  sprintf(buf,"%u ",rrp->i);
  CSP_ADDSTR(buf);
  return csp_qstring(vb,rrp->str);
}

static adns_status cs_manyistr(vbuf *vb, const void *datap) {
  const adns_rr_intstr *const *rrp= datap;
  const adns_rr_intstr *current;
  adns_status st;
  int spc;

  for (spc=0, current= *rrp; current->i >= 0; current++) {
    if (spc) CSP_ADDSTR(" ");
    st= csp_textdata(vb,current->str,current->i); if (st) return st;
  }
  return adns_s_ok;
}

static void mf_str(adns_query qu, void *datap) {
  char **rrp= datap;

  adns__makefinal_str(qu,rrp);
}

static void mf_intstr(adns_query qu, void *datap) {
  adns_rr_intstr *rrp= datap;

  adns__makefinal_str(qu,&rrp->str);
}

static adns_status csp_hostaddr(vbuf *vb, const adns_rr_hostaddr *rrp) {
  const char *to_add;
  adns_status st;
  int i;

  st= csp_qstring(vb,rrp->host); if (st) return st;

  if (rrp->astatus) {
    CSP_ADDSTR(" - ");
    CSP_ADDSTR(adns_strerror(rrp->astatus));
  } else {
    assert(rrp->naddrs > 0);
    for (i=0, to_add= ": "; i<rrp->naddrs; i++, to_add= ", ") {
      CSP_ADDSTR(to_add);
      st= csp_addr(vb,&rrp->addrs[i]);
    }
  }
  return adns_s_ok;
}

static adns_status cs_hostaddr(vbuf *vb, const void *datap) {
  const adns_rr_hostaddr *rrp= datap;

  return csp_hostaddr(vb,rrp);
}

static adns_status cs_inthostaddr(vbuf *vb, const void *datap) {
  const adns_rr_inthostaddr *rrp= datap;
  char buf[10];

  sprintf(buf,"%u ",rrp->i);
  CSP_ADDSTR(buf);

  return csp_hostaddr(vb,&rrp->ha);
}
  
static void mfp_hostaddr(adns_query qu, adns_rr_hostaddr *rrp) {
  void *tablev;

  adns__makefinal_str(qu,&rrp->host);
  tablev= rrp->addrs;
  adns__makefinal_block(qu, &tablev, rrp->naddrs*sizeof(*rrp->addrs));
  rrp->addrs= tablev;
}

static void mf_hostaddr(adns_query qu, void *datap) {
  adns_rr_hostaddr *rrp= datap;

  mfp_hostaddr(qu,rrp);
}

static void mf_inthostaddr(adns_query qu, void *datap) {
  adns_rr_inthostaddr *rrp= datap;

  mfp_hostaddr(qu,&rrp->ha);
}

static void mf_manyistr(adns_query qu, void *datap) {
  adns_rr_intstr **rrp= datap;
  adns_rr_intstr *te, *table;
  void *tablev;
  int tc;

  for (tc=0, te= *rrp; te->i >= 0; te++, tc++);
  tablev= *rrp;
  adns__makefinal_block(qu,&tablev,sizeof(*te)*(tc+1));
  *rrp= table= tablev;
  for (te= *rrp; te->i >= 0; te++)
    adns__makefinal_str(qu,&te->str);
}

static void mf_flat(adns_query qu, void *data) { }

#define TYPE_SF(size,func,cp,free) size, pa_##func, mf_##free, cs_##cp
#define TYPE_SN(size,func,cp)      size, pa_##func, mf_flat, cs_##cp
#define TYPESZ_M(member)           (sizeof(*((adns_answer*)0)->rrs.member))
#define TYPE_MF(memb,parse)        TYPE_SF(TYPESZ_M(memb),parse,memb,memb)
#define TYPE_MN(memb,parse)        TYPE_SN(TYPESZ_M(memb),parse,memb)

#define DEEP_MEMB(memb) TYPESZ_M(memb), mf_##memb, cs_##memb
#define FLAT_MEMB(memb) TYPESZ_M(memb), mf_flat, cs_##memb

/* TYPE_<ms><nf>
 *  ms is M  specify member name
 *     or S  specify size explicitly
 *  nf is F  full memory management, dependent on member name or specified func
 *        N  no memory management required
 */

static const typeinfo typeinfos[] = {
  /* Must be in ascending order of rrtype ! */
  /* rr type code   rrt     fmt      mem.mgmt  member        parser         comparer */
  							     
  { adns_r_a,       "A",     0,      FLAT_MEMB(inaddr),      pa_inaddr,    di_inaddr   },
  { adns_r_ns_raw,  "NS",   "raw",   DEEP_MEMB(str),         pa_host_raw,  0           },
  { adns_r_cname,   "CNAME", 0,      DEEP_MEMB(str),         pa_host_raw,  0           },
#if 0 /*fixme*/	    	                    	       	     		  	     
  { adns_r_soa_raw, "SOA",  "raw",   DEEP_MEMB(soa),         pa_soa,       0           },
#endif							     		 	     
  { adns_r_ptr_raw, "PTR",  "raw",   DEEP_MEMB(str),         pa_host_raw,  0           },
#if 0 /*fixme*/	    	                    	       	     		  	     
  { adns_r_hinfo,   "HINFO", 0,      DEEP_MEMB(strpair),     pa_hinfo,     0           },
#endif							     		 	     
  { adns_r_mx_raw,  "MX",   "raw",   DEEP_MEMB(intstr),      pa_mx_raw,    di_mx_raw   },
  { adns_r_txt,     "TXT",   0,      DEEP_MEMB(manyistr),    pa_txt,       0           },
#if 0 /*fixme*/	    	                    	       	     		  	     
  { adns_r_rp_raw,  "RP",   "raw",   DEEP_MEMB(strpair),     pa_rp,        0           },
#endif							     		 	     
   		      	                                     		  	     
  { adns_r_addr,    "A",  "addr",    FLAT_MEMB(addr),        pa_addr,      di_addr     },
  { adns_r_ns,      "NS", "+addr",   DEEP_MEMB(hostaddr),    pa_hostaddr,  di_hostaddr },
#if 0 /*fixme*/	    	                    	       	     		  	     
  { adns_r_ptr,     "PTR","checked", DEEP_MEMB(str),         pa_ptr,       0           },
#endif
  { adns_r_mx,      "MX", "+addr",   DEEP_MEMB(inthostaddr), pa_mx,        di_mx       },
   		      	                                  		   
#if 0 /*fixme*/
  { adns_r_soa,     "SOA","822",     DEEP_MEMB(soa),         pa_soa,        0          },
  { adns_r_rp,      "RP", "822",     DEEP_MEMB(strpair),     pa_rp,         0          },
#endif
};

const typeinfo *adns__findtype(adns_rrtype type) {
  const typeinfo *begin, *end, *mid;

  begin= typeinfos;  end= typeinfos+(sizeof(typeinfos)/sizeof(typeinfo));

  while (begin < end) {
    mid= begin + ((end-begin)>>1);
    if (mid->type == type) return mid;
    if (type > mid->type) begin= mid+1;
    else end= mid;
  }
  return 0;
}
