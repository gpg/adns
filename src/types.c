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

#include "internal.h"

static adns_status rp_inaddr(adns_state ads, adns_query qu, int serv,
			     const byte *dgram, int dglen, int cbyte, int max,
			     void *store_r) {
  struct in_addr *dr= store_r;
  
  if (max-cbyte != 4) return adns_s_invaliddata;
  memcpy(dr,dgram+cbyte,4);
  return adns_s_ok;
}

static adns_status rmf_null(adns_state ads, adns_query qu, void *data) { }

#define TYPE_SF(size,func,free)    size, rp_#func, rmf_#free
#define TYPE_SN(size,func)         size, rp_#func, rmf_null
#define TYPESZ_M(member)           (sizeof(((adns_answer*)0)->rrs.member))
#define TYPE_MF(member,parse)      TYPE_SF(TYPESZ_M(member),parse,member)
#define TYPE_MN(member,parse)      TYPE_SN(TYPESZ_M(member),parse)

/* TYPE_<ms><nf>
 *  ms is M  specify member name
 *     or S  specify size explicitly
 *  nf is F  full memory management, dependent on member name or specified func
 *        N  no memory management required
 */

static const typeinfo typeinfos[] = {
  /* Must be in ascending order of rrtype ! */
  /* rr type code     name             style     member     size  parser */
  
  {  adns_r_a,        "A",             TYPE_MN(  inaddr,          inaddr       ) },
#if 0 /*fixme*/		                   	       
  {  adns_r_ns_raw,   "NS(raw)",       TYPE_MF(  str,             domain_raw   ) },
  {  adns_r_cname,    "CNAME",         TYPE_MF(  str,             domain_raw   ) },
  {  adns_r_soa_raw,  "SOA(raw)",      TYPE_MF(  soa,             soa          ) },
  {  adns_r_null,     "NULL",          TYPE_SN(              0,   null         ) },
  {  adns_r_ptr_raw,  "PTR(raw)",      TYPE_MF(  str,             domain_raw   ) },
  {  adns_r_hinfo,    "HINFO",         TYPE_MF(  strpair,         hinfo        ) },
  {  adns_r_mx_raw,   "MX(raw)",       TYPE_MF(  intstr,          mx_raw       ) },
  {  adns_r_txt,      "TXT",           TYPE_MF(  str,             txt          ) },
  {  adns_r_rp_raw,   "RP(raw)",       TYPE_MF(  strpair,         rp           ) },
    		       	                                      
  {  adns_r_ns,       "NS(+addr)",     TYPE_MF(  dmaddr,          dmaddr       ) },
  {  adns_r_ptr,      "PTR(checked)",  TYPE_MF(  str,             ptr          ) },
  {  adns_r_mx,       "MX(+addr)",     TYPE_MF(  intdmaddr,       mx           ) },
    		       	                                      
  {  adns_r_soa,      "SOA(822)",      TYPE_MF(  soa,             soa          ) },
  {  adns_r_rp,       "RP(822)",       TYPE_MF(  strpair,         rp           ) },
#endif
};

const typeinfo adns__findtype(adns_rrtype type) {
  const typeinfo *begin, *end;

  begin= typeinfos;  end= typeinfos+(sizeof(typeinfos)/sizeof(typeinfo));

  while (begin < end) {
    mid= begin + ((end-begin)>>1);
    if (mid->type == type) return mid;
    if (type > mid->type) begin= mid+1;
    else end= mid;
  }
  return 0;
}
