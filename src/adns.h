/**/

#ifndef ADNS_H_INCLUDED
#define ADNS_H_INCLUDED

typedef struct adns__state adns_state;
typedef struct adns__query adns_query;

typedef enum {
  adns_if_noenv=      0x0001, /* do not look at environment */
  adns_if_noerrprint= 0x0002, /* never print output to stderr */
  adns_if_debug=      0x0004, /* print debugging output to stderr */
} adns_initflags;

typedef enum {
  adns_f_search=     0x0001, /* use the searchlist */
  adns_f_usevc=      0x0002, /* use a virtual circuit (TCP connection) */
} adns_queryflags;

typedef enum {
  adns_rrttype_mask=  0x0fff,
  adns_qtf_deref=     0x1000,
  adns_qtf_mailconv=  0x2000,
  adns_r_none=             0,
  adns_r_a=                1,
  adns_r_ns_raw=           2,
  adns_r_ns=                  adns_r_ns_raw|adns_qtf_deref,
  adns_r_cname=            5,
  adns_r_soa_raw=          6,
  adns_r_soa=                 adns_r_soa_raw|adns_qtf_mailconv,
  adns_r_null=            10,
  adns_r_ptr_raw=         12,
  adns_r_ptr=                 adns_r_ptr_raw|adns_rf_deref,
  adns_r_hinfo=           13,  
  adns_r_mx_raw=          15,
  adns_r_mx=                  adns_r_mx_raw|adns_qtf_deref,
  adns_r_txt=             16,
  adns_r_rp_raw           17,
  adns_r_rp=                  adns_r_rp_raw|adns_qtf_mailconv
} adns_rrtype;

typedef enum {
  adns_s_ok,
  adns_s_notresponding,
  adns_s_serverfailure,
  adns_s_unknownqtype,
  adns_s_remoteerror,
  adns_s_max_tempfail= 99,
  adns_s_nxdomain,
  adns_s_norecord,
  adns_s_invaliddomain
} adns_status;

/* In dereferenced answers, multiple addresses show up as multiple
 * answers with all the dm pointers being the same.  If no
 * address is available (permanent failure) then INADDR_NONE is
 * used. */

struct adns_answer {
  adns_status status;
  char *cname; /* always NULL if query was for CNAME records */
  adns_rrtype type;
  int nrrs;
  union {
    struct in_addr inaddr[1];                                          /* a */
    char (*str)[1];                     /* ns_raw, cname, ptr, ptr_raw, txt */
    struct { char *dm; struct in_addr addr; } dmaddr;                 /* ns */
    struct { char *a, *b; } strpair[1];                /* hinfo, rp, rp_raw */
    struct { int pref; char *dm; struct in_addr addr; } intdmaddr[1]; /* mx */
    struct { int pref; char *str; } intstr[1]; /* mx_raw */
    struct {
      char *ns0, *rp;
      unsigned long serial, refresh, retry, expire, minimum;
    } soa[1]; /* soa, soa_raw */
    /* NULL is empty */
  } rrs;
};

/* Memory management:
 *  adns_state and adns_query are actually pointers to malloc'd state;
 *  On submission questions are copied, including the owner domain;
 *  Answers are malloc'd as a single piece of memory.
 * query_io:
 *  Must always be non-null pointer;
 *  If *query_io is 0 to start with then any query may be returned;
 *  If *query_io is !0 adns_query then only that query may be returned.
 * Errors:
 *  Return values are 0 or an errno value;
 *  Seriously fatal system errors (eg, failure to create sockets,
 *  malloc failure, etc.) return errno values;
 *  Other errors (nameserver failure, timed out connections, &c)
 *  are returned in the status field of the answer.  If status is
 *  nonzero then nrrs will be 0, otherwise it will be >0.
 *  type will always be the type requested;
 *  If no (appropriate) requests are done adns_query returns EWOULDBLOCK;
 *  If no requests are outstanding adns_query and adns_wait return ESRCH;
 *  If malloc failure occurs during internal allocation or processing
 *  ands_query, _wait and _answer set *answer to 0.
 */

int adns_init(adns_state *newstate_r);

int adns_synchronous(adns_state ads,
		     const char *owner,
		     adns_rrtype type,
		     int flags,
		     struct adns_answer *answer);

int adns_submit(adns_state ads,
		const char *owner,
		adns_rrtype type,
		int flags,
		void *context,
		const struct adns_query *query_r);

int adns_query(adns_state ads,
	       adns_query *query_io,
	       struct adns_answer *answer,
	       void *context_r);

int adns_wait(adns_state ads,
	      adns_query *query_io,
	      struct adns_answer *answer,
	       void *context_r);

int adns_cancel(adns_state ads, adns_query query);

int adns_finish(adns_state);

void adns_event(adns_state, fd_set *readfds_mod,
		fd_set *writefds_mod, fd_set *exceptfds_mod,
		int *maxfd_mod, struct timeval *tv_mod);
/* You may call this with *_mod=0 to have a simple callback,
   or with *fds_mod=*maxfd_mod=0 but tv_mod!=0 if you are
   not going to sleep, or with all !=0 if you are going to sleep. */

/* Example expected/legal calling sequences:
 *  adns_init
 *  adns_submit 1
 *  adns_submit 2
 *  adns_submit 3
 *  adns_wait 1
 *  adns_query 3 -> EWOULDBLOCK
 *  adns_wait 2
 *  adns_wait 3
 *  ....
 *  adns_finish
 *
 *  adns_init
 *  adns_submit ...
 *  loop {
 *   adns_query
 *   adns_interest
 *   select
 *   adns_callback
 *   other things
 *  }
 */

#endif
