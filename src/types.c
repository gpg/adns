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

static void fr_null(adns_query qu, void *data) { }

#define TYPE_SF(size,func,cp,free) size, pa_##func, fr_##free, cs_##cp
#define TYPE_SN(size,func,cp)      size, pa_##func, fr_null, cs_##cp
#define TYPESZ_M(member)           (sizeof(((adns_answer*)0)->rrs.member))
#define TYPE_MF(memb,parse)        TYPE_SF(TYPESZ_M(memb),parse,memb,memb)
#define TYPE_MN(memb,parse)        TYPE_SN(TYPESZ_M(memb),parse,memb)

#define DEEP_MEMB(memb) TYPESZ_M(memb), fr_##memb, cs_##memb
#define FLAT_MEMB(memb) TYPESZ_M(memb), fr_null, cs_##memb
#define NULL_MEMB       0, fr_null, cs_null

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
#if 0 /*fixme*/	    	                    	       	  		   
  { adns_r_ns_raw,  "NS",   "raw",     DEEP_MEMB(str),       pa_domain_raw  },
  { adns_r_cname,   "CNAME", 0,        DEEP_MEMB(str),       pa_domain_raw  },
  { adns_r_soa_raw, "SOA",  "raw",     DEEP_MEMB(soa),       pa_soa         },
  { adns_r_null,    "NULL",  0,        NULL_MEMB,            pa_null        },
  { adns_r_ptr_raw, "PTR",  "raw",     DEEP_MEMB(str),       pa_domain_raw  },
  { adns_r_hinfo,   "HINFO", 0,        DEEP_MEMB(strpair),   pa_hinfo       },
  { adns_r_mx_raw,  "MX",   "raw",     DEEP_MEMB(intstr),    pa_mx_raw      },
  { adns_r_txt,     "TXT",   0,        DEEP_MEMB(str),       pa_txt         },
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
