/*
 * adh-query.c
 * - useful general-purpose resolver client program
 *   make queries and print answers
 */
/*
 *  This file is
 *    Copyright (C) 1997-1999 Ian Jackson <ian@davenant.greenend.org.uk>
 *
 *  It is part of adns, which is
 *    Copyright (C) 1997-1999 Ian Jackson <ian@davenant.greenend.org.uk>
 *    Copyright (C) 1999 Tony Finch <dot@dotat.at>
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

#include "adnshost.h"

adns_state ads;
struct outstanding_list outstanding;

static unsigned long idcounter;

#define STATUSTYPEMAX(v) { adns_s_max_##v, #v }
static const struct statustypemax {
  adns_status smax;
  const char *abbrev;
} statustypemaxes[]= {
  { adns_s_ok, "ok" },
  STATUSTYPEMAX(localfail),
  STATUSTYPEMAX(remotefail),
  STATUSTYPEMAX(tempfail),
  STATUSTYPEMAX(misconfig),
  STATUSTYPEMAX(misquery),
  STATUSTYPEMAX(permfail),
};

void ensure_adns_init(void) {
  int r;
  
  if (ads) return;

  if (signal(SIGPIPE,SIG_IGN) == SIG_ERR) sysfail("ignore SIGPIPE",errno);
  r= adns_init(&ads,
	       adns_if_noautosys|adns_if_nosigpipe |
	       (ov_env ? 0 : adns_if_noenv) |
	       ov_verbose,
	       0);
  if (r) sysfail("adns_init",r);
}

void query_do(const char *domain) {
  struct query_node *qun;
  char idbuf[20];
  int r;

  qun= malloc(sizeof(*qun));
  qun->pqfr= ov_pqfr;
  if (ov_id) {
    qun->id= xstrsave(ov_id);
  } else {
    sprintf(idbuf,"%lu",idcounter++);
    idcounter &= 0x0fffffffflu;
    qun->id= xstrsave(idbuf);
  }
  
  r= adns_submit(ads, domain,
		 ov_type == adns_r_none ? adns_r_addr : ov_type,
		 (ov_search ? adns_qf_search : 0) |
		 (ov_tcp ? adns_qf_usevc : 0) |
		 (ov_pqfr.show_owner ? adns_qf_owner : 0) |
		 (ov_qc_query ? adns_qf_quoteok_query : 0) |
		 (ov_qc_anshost ? adns_qf_quoteok_anshost : 0) |
		 (ov_qc_cname ? 0 : adns_qf_quoteok_cname) |
		 ov_cname,
		 qun,
		 &qun->qu);
  if (r) sysfail("adns_submit",r);

  LIST_LINK_TAIL(outstanding,qun);
}

static void print_withspace(const char *str) {
  if (printf("%s ", str) == EOF) outerr();
}

static void print_ttl(struct query_node *qun, adns_answer *answer) {
  unsigned long ttl;
  time_t now;
  
  switch (qun->pqfr.ttl) {
  case tm_none:
    return;
  case tm_rel:
    if (time(&now) == (time_t)-1) sysfail("get current time",errno);
    ttl= answer->expires < now ? 0 : answer->expires - now;
    break;
  case tm_abs:
    ttl= answer->expires;
    break;
  default:
    abort();
  }
  if (printf("%lu ",ttl) == EOF) outerr();
}

static void print_owner_ttl(struct query_node *qun, adns_answer *answer) {
  if (qun->pqfr.show_owner) print_withspace(answer->owner);
  print_ttl(qun,answer);
}

static void print_status(adns_status st, struct query_node *qun, adns_answer *answer) {
  int stnmin, stnmax, stn;
  const char *statusabbrev, *statusstring;

  stnmin= 0;
  stnmax= sizeof(statustypemaxes)/sizeof(statustypemaxes[0]);
  while (stnmin < stnmax) {
    stn= (stnmin+stnmax)>>1;
    if (st > statustypemaxes[stn].smax) stnmin= stn+1; else stnmax= stn;
  }
  stn= stnmin;
  assert(statustypemaxes[stn].smax >= st);
  
  if (rcode < stn) rcode= stn;

  statusabbrev= adns_errabbrev(st);
  statusstring= adns_strerror(st);
  assert(!strchr(statusstring,'"'));

  if (printf("%s %d %s ", statustypemaxes[stn].abbrev, st, statusabbrev)
      == EOF) outerr();
  print_owner_ttl(qun,answer);
  if (qun->pqfr.show_cname)
    print_withspace(answer->cname ? answer->cname : "$");
  if (printf("\"%s\"\n", statusstring) == EOF) outerr();
}

void query_done(struct query_node *qun, adns_answer *answer) {
  adns_status st, ist;
  int rrn, nrrs;
  const char *rrp, *realowner, *typename;
  char *datastr;

  if (ov_pipe) setnonblock(1,0);

  st= answer->status;
  nrrs= answer->nrrs;
  if (ov_asynch) {
    if (printf("%s %d", qun->id, nrrs) == EOF) outerr();
    print_status(st,qun,answer);
  } else {
    if (st) {
      if (fputs("; failed",stdout) == EOF) outerr();
      print_status(st,qun,answer);
    } else if (answer->cname) {
      print_owner_ttl(qun,answer);
      if (printf("CNAME %s\n",answer->cname) == EOF) outerr();
    }
  }
  if (qun->pqfr.show_owner) {
    realowner= answer->cname ? answer->cname : answer->owner;;
    assert(realowner);
  } else {
    realowner= 0;
  }
  if (nrrs) {
    for (rrn=0, rrp = answer->rrs.untyped;
	 rrn < nrrs;
	 rrn++, rrp += answer->rrsz) {
      if (realowner) print_withspace(realowner);
      print_ttl(qun,answer);
      ist= adns_rr_info(answer->type, &typename, 0, 0, rrp, &datastr);
      if (ist == adns_s_nomemory) sysfail("adns_rr_info failed",ENOMEM);
      assert(!ist);
      if (qun->pqfr.show_type) print_withspace(typename);
      if (printf("%s\n",datastr) == EOF) outerr();
      free(datastr);
    }
  }
  if (fflush(stdout)) outerr();
  LIST_UNLINK(outstanding,qun);
  free(answer);
  free(qun->id);
  free(qun);
}

void of_asynch_id(const struct optioninfo *oi, const char *arg) {
  free(ov_id);
  ov_id= xstrsave(arg);
}

void of_cancel_id(const struct optioninfo *oi, const char *arg) { abort(); }

