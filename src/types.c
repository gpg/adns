/**/

#include "internal.h"

#define TYRRSZ(rrtype,size,func) { (rrtype), (size), (func) }

#define TYRRSZ(sizememb) (sizeof(((adns_answer*)0)->rrs.sizememb))

static const typeinfo typeinfos[] = {
  /* Must be in ascending order of rrtype ! */
  
  {    adns_r_a,               TYRR(inaddr),       rpf_inaddr           },
  {    adns_r_ns_raw,          TYRR(str),          rpf_domain_raw       },
  {    adns_r_cname,           TYRR(str),          rpf_domain_raw       },
  {    adns_r_soa_raw,         TYRR(soa),          rpf_soa              },
  {    adns_r_null,            0,                  rpf_null             },
  {    adns_r_ptr_raw,         TYRR(str),          rpf_domain_raw       },
  {    adns_r_hinfo,           TYRR(strpair),      rpf_hinfo            },
  {    adns_r_mx_raw,          TYRR(intstr),       rpf_mx_raw           },
  {    adns_r_txt,             TYRR(str),          rpf_txt              },
  {    adns_r_rp_raw,          TYRR(strpair),      rpf_rp               },

  {    adns_r_ns,              TYRR(dmaddr),       rpf_dmaddr           },
  {    adns_r_ptr,             TYRR(str),          rpf_ptr              },
  {    adns_r_mx,              TYRR(intdmaddr),    rpf_mx               },

  {    adns_r_soa,             TYRR(soa),          rpf_soa              },
  {    adns_r_rp,              TYRR(strpair),      rpf_rp               },
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
