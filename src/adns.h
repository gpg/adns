/*
 * Copyright (C)1998 Ian Jackson.
 * This version provided for review and comment only.
 *
 * $Id$
 */

#ifndef ADNS_H_INCLUDED
#define ADNS_H_INCLUDED

#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>

typedef struct adns__state *adns_state;
typedef struct adns__query *adns_query;

typedef enum {
  adns_if_noenv=        0x0001, /* do not look at environment */
  adns_if_noerrprint=   0x0002, /* never print output to stderr (_debug overrides) */
  adns_if_noserverwarn= 0x0004, /* do not warn to stderr about duff nameservers etc */
  adns_if_debug=        0x0008, /* enable all output to stderr plus debug msgs */
  adns_if_noautosys=    0x0010, /* do not make syscalls at every opportunity */
} adns_initflags;

typedef enum {
  adns_qf_search=     0x0001, /* use the searchlist */
  adns_qf_usevc=      0x0002, /* use a virtual circuit (TCP connection) */
  adns_qf_anyquote=   0x0004,
  adns_qf_loosecname= 0x0008, /* allow refs to CNAMEs - without, get _s_cname */
  adns_qf_nocname=    0x0010, /* don't follow CNAMEs, instead give _s_cname */
} adns_queryflags;

typedef enum {
  adns__rrt_typemask=  0x0ffff,
  adns__qtf_deref=     0x10000, /* dereference domains and perhaps produce extra data */
  adns__qtf_mail822=   0x20000, /* make mailboxes be in RFC822 rcpt field format */
  adns__qtf_masterfmt= 0x80000, /* convert RRs to master file format, return as str */
  
  adns_r_none=               0,
  
  adns_r_a=                  1,
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
  
} adns_rrtype;

/* In queries without qtf_anyquote, all domains must have standard
 * legal syntax.  In queries _with_ qtf_anyquote, domains in the query
 * or response may contain any characters, quoted according to
 * RFC1035 5.1.  On input to adns, the char* is a pointer to the
 * interior of a " delimited string, except that " may appear in it,
 * and on output, the char* is a pointer to a string which would be
 * legal either inside or outside " delimiters, and any characters
 * not usually legal in domain names will be quoted as \X
 * (if the character is 33-126 except \ and ") or \DDD.
 *
 * _qtf_anyquote is ignored for _mf queries.
 *
 * Do not ask for _raw records containing mailboxes without
 * specifying _qf_anyquote.
 */

typedef enum {
  adns_s_ok,
  adns_s_timeout,
  adns_s_nolocalmem,
  adns_s_allservfail,
  adns_s_servfail,
  adns_s_notimplemented,
  adns_s_refused,
  adns_s_reasonunknown,
  adns_s_norecurse,
  adns_s_serverfaulty,
  adns_s_unknownreply,
  adns_s_max_tempfail= 99,
  adns_s_inconsistent, /* PTR gives domain whose A does not match */
  adns_s_cname, /* CNAME found where data eg A expected (not if _qf_loosecname) */
  /* fixme: implement _s_cname */
  adns_s_max_remotemisconfig= 199,
  adns_s_nxdomain,
  adns_s_nodata,
  adns_s_invaliddomain,
  adns_s_domaintoolong,
} adns_status;

typedef struct {
  char *dm;
  adns_status astatus;
  int naddrs; /* temp fail => -1, perm fail => 0, s_ok => >0 */
  struct in_addr *addrs;
} adns_rr_dmaddr;

typedef struct {
  char *a, *b;
} adns_rr_strpair;

typedef struct {
  int i;
  adns_rr_dmaddr dmaddr;
} adns_rr_intdmaddr;

typedef struct {
  int i;
  char *str;
} adns_rr_intstr;

typedef struct {
  char *ns0, *rp;
  unsigned long serial, refresh, retry, expire, minimum;
} adns_rr_soa;

typedef struct {
  adns_status status;
  char *cname; /* always NULL if query was for CNAME records */
  adns_rrtype type;
  int nrrs;
  union {
    char *(*str);                  /* ns_raw, cname, ptr, ptr_raw, txt, <any>_mf */
    struct in_addr *inaddr;        /* a */
    adns_rr_dmaddr *dmaddr;        /* ns */
    adns_rr_strpair *strpair;      /* hinfo, rp, rp_raw */
    adns_rr_intdmaddr *intdmaddr;  /* mx */
    adns_rr_intstr *intstr;        /* mx_raw */
    adns_rr_soa *soa;              /* soa, soa_raw */
    /* NULL is empty */
  } rrs;
} adns_answer;

/* Memory management:
 *  adns_state and adns_query are actually pointers to malloc'd state;
 *  On submission questions are copied, including the owner domain;
 *  Answers are malloc'd as a single piece of memory; pointers in the
 *  answer struct point into further memory in the answer.
 * query_io:
 *  Must always be non-null pointer;
 *  If *query_io is 0 to start with then any query may be returned;
 *  If *query_io is !0 adns_query then only that query may be returned.
 *  If the call is successful, *query_io, *answer_r, and *context_r
 *  will all be set.
 * Errors:
 *  Return values are 0 or an errno value;
 *  Seriously fatal system errors (eg, failure to create sockets,
 *  malloc failure, etc.) return errno values;
 *  Other errors (nameserver failure, timed out connections, &c)
 *  are returned in the status field of the answer.  If status is
 *  nonzero then nrrs will be 0, otherwise it will be >0.
 *  type will always be the type requested;
 *  If no (appropriate) requests are done adns_check returns EWOULDBLOCK;
 *  If no (appropriate) requests are outstanding adns_query and adns_wait return ESRCH;
 */

int adns_init(adns_state *newstate_r, adns_initflags flags, FILE *diagfile/*0=>stderr*/);

int adns_synchronous(adns_state ads,
		     const char *owner,
		     adns_rrtype type,
		     adns_queryflags flags,
		     adns_answer **answer_r);
/* Will not return EINTR. */

/* NB: if you set adns_if_noautosys then _submit and _check do not
 * make any system calls; you must use adns_callback (possibly after
 * adns_interest) to actually get things to happen.
 */

int adns_submit(adns_state ads,
		const char *owner,
		adns_rrtype type,
		adns_queryflags flags,
		void *context,
		adns_query *query_r);

int adns_check(adns_state ads,
	       adns_query *query_io,
	       adns_answer **answer_r,
	       void **context_r);

int adns_wait(adns_state ads,
	      adns_query *query_io,
	      adns_answer **answer_r,
	      void **context_r);
/* Might return EINTR - if so, try again */

void adns_cancel(adns_state ads, adns_query query);

int adns_finish(adns_state);

int adns_callback(adns_state, int maxfd, const fd_set *readfds, const fd_set *writefds,
		  const fd_set *exceptfds);
/* Gives adns flow-of-control for a bit.  This will never block.
 * If maxfd == -1 then adns will check (make nonblocking system calls on)
 * all of its own filedescriptors; otherwise it will only use those
 * < maxfd and specified in the fd_set's, as if select had returned them.
 * Other fd's may be in the fd_sets, and will be ignored.
 * _callback returns how many adns fd's were in the various sets, so
 * you can tell if your select handling code has missed something and is going awol.
 *
 * May also return -1 if a critical syscall failed, setting errno.
 */

void adns_interest(adns_state, int *maxfd_io, fd_set *readfds_io,
		   fd_set *writefds_io, fd_set *exceptfds_io,
		   struct timeval **tv_mod, struct timeval *tv_buf);
/* Find out file descriptors adns is interested in, and when it
 * would like the opportunity to time something out.  If you do not plan to
 * block then tv_mod may be 0.  Otherwise, tv_mod may point to 0 meaning
 * you have no timeout of your own, in which case tv_buf must be non-null and
 * _interest may fill it in and set *tv_mod=tv_buf.
 * readfds, writefds, exceptfds and maxfd may not be 0.
 */

/* Example expected/legal calling sequences:
 *  adns_init
 *  adns_submit 1
 *  adns_submit 2
 *  adns_submit 3
 *  adns_wait 1
 *  adns_check 3 -> EWOULDBLOCK
 *  adns_wait 2
 *  adns_wait 3
 *  ....
 *  adns_finish
 *
 *  adns_init _noautosys
 *  loop {
 *   adns_interest
 *   select
 *   adns_callback
 *   ...
 *   adns_submit / adns_check
 *   ...
 *  }
 */

const char *adns_strerror(adns_status st);

#endif
