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

#include <arpa/inet.h>

#include "internal.h"

static adns_status pa_inaddr(adns_query qu, int serv,
			     const byte *dgram, int dglen, int cbyte, int max,
			     void *store_r) {
  struct in_addr *dr= store_r;
  
  if (max-cbyte != 4) return adns_s_invaliddata;
  memcpy(dr,dgram+cbyte,4);
  return adns_s_ok;
}

static adns_status cs_inaddr(vbuf *vb, const void *data) {
  const struct in_addr *dp= data;
  const char *ia;

  ia= inet_ntoa(*dp); assert(ia);
  return adns__vbuf_appendstr(vb,ia) ? adns_s_ok : adns_s_nolocalmem;
}

static adns_status pa_domain_raw(adns_query qu, int serv,
				 const byte *dgram, int dglen, int cbyte, int max,
				 void *store_r) {
  char **dpp= store_r;
  adns_status st;
  vbuf vb;
  char *dp;

  adns__vbuf_init(&vb);
  st= adns__parse_domain(qu->ads,serv,qu,&vb,qu->flags,
			 dgram,dglen, &cbyte,max);
  if (st) goto x_error;

  dp= adns__alloc_interim(qu,vb.used+1);
  if (!dp) { st= adns_s_nolocalmem; goto x_error; }

  dp[vb.used]= 0;
  memcpy(dp,vb.buf,vb.used);

  if (cbyte != max) { st= adns_s_invaliddata; goto x_error; }

  st= adns_s_ok;
  *dpp= dp;

 x_error:
  adns__vbuf_free(&vb);
  return st;
}

static adns_status pa_txt(adns_query qu, int serv,
			  const byte *dgram, int dglen, int cbyte, int max,
			  void *store_r) {
  vbuf vb;

  adns__vbuf_init(&vb);

  while (dg
  char *bp;

  max-= cbyte;
  dgram+= cbyte;
  
  bp= adns__alloc_interim(qu,max+1); if (!bp) return adns_s_nolocalmem;
  bp[max]= 0;
  memcpy(bp,dgram,max);
  *(char**)store_r= bp;
  return adns_s_ok;
}

static void mf_str(adns_query qu, void *data) {
  char **ddp= data;

  adns__makefinal_str(qu,ddp);
}

static int csp_qstring(vbuf *vb, const char *dp) {
  unsigned char ch;
  char buf[10];

  if (!adns__vbuf_append(vb,"\"",1)) return 0;

  while ((ch= *dp++)) {
    if (ch >= 32 && ch <= 126 && ch != '"' && ch != '\\') {
      if (!adns__vbuf_append(vb,&ch,1)) return 0;
    } else {
      sprintf(buf,"\\%02x",ch);
      if (!adns__vbuf_appendstr(vb,buf)) return 0;
    }
  }
  
  if (!adns__vbuf_append(vb,"\"",1)) return 0;
  return 1;
}

static adns_status cs_str(vbuf *vb, const void *data) {
  const char *const *dpp= data;

  return csp_qstring(vb,*dpp) ? adns_s_ok : adns_s_nolocalmem;
}

static void mf_flat(adns_query qu, void *data) { }

#define TYPE_SF(size,func,cp,free) size, pa_##func, mf_##free, cs_##cp
#define TYPE_SN(size,func,cp)      size, pa_##func, mf_flat, cs_##cp
#define TYPESZ_M(member)           (sizeof(((adns_answer*)0)->rrs.member))
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
  /* rr type code   rrt     fmt        mem.mgmt  member      parser        */
  
  { adns_r_a,       "A",     0,        FLAT_MEMB(inaddr),    pa_inaddr      },
  { adns_r_ns_raw,  "NS",   "raw",     DEEP_MEMB(str),       pa_domain_raw  },
  { adns_r_cname,   "CNAME", 0,        DEEP_MEMB(str),       pa_domain_raw  },
#if 0 /*fixme*/	    	                    	       	  		   
  { adns_r_soa_raw, "SOA",  "raw",     DEEP_MEMB(soa),       pa_soa         },
#endif
  { adns_r_ptr_raw, "PTR",  "raw",     DEEP_MEMB(str),       pa_domain_raw  },
#if 0 /*fixme*/
  { adns_r_hinfo,   "HINFO", 0,        DEEP_MEMB(strpair),   pa_hinfo       },
  { adns_r_mx_raw,  "MX",   "raw",     DEEP_MEMB(intstr),    pa_mx_raw      },
#endif
  { adns_r_txt,     "TXT",   0,        DEEP_MEMB(str),       pa_txt         },
#if 0 /*fixme*/
  { adns_r_rp_raw,  "RP",   "raw",     DEEP_MEMB(strpair),   pa_rp          },
   		      	                                  		   
  { adns_r_ns,      "NS",   "+addr",   DEEP_MEMB(dmaddr),    pa_dmaddr      },
  { adns_r_ptr,     "PTR",  "checked", DEEP_MEMB(str),       pa_ptr         },
  { adns_r_mx,      "MX",   "+addr",   DEEP_MEMB(intdmaddr), pa_mx          },
   		      	                                  		   
  { adns_r_soa,     "SOA",  "822",     DEEP_MEMB(soa),       pa_soa         },
  { adns_r_rp,      "RP",   "822",     DEEP_MEMB(strpair),   pa_rp          },
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
