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

struct query_node {
  struct query_node *next, *back;
  struct perqueryflags_remember pqfr;
  char *id;
  adns_query qu;
};

static struct { struct query_node *head, *tail; } outstanding;

static unsigned long idcounter;

void domain_do(const char *domain) {
  struct query_node *qun;
  char idbuf[20];
  int r;

  if (!ads) {
    if (signal(SIGPIPE,SIG_IGN) == SIG_ERR) sysfail("ignore SIGPIPE",errno);
    r= adns_init(&ads,
		 adns_if_noautosys|adns_if_nosigpipe |
		 (ov_env ? 0 : adns_if_noenv) |
		 ov_verbose,
		 0);
    if (r) sysfail("adns_init",r);
  }

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

void of_asynch_id(const struct optioninfo *oi, const char *arg) { abort(); }
void of_cancel_id(const struct optioninfo *oi, const char *arg) { abort(); }
