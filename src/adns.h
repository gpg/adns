/**/

#ifndef ADNS_H_INCLUDED
#define ADNS_H_INCLUDED

#include <sys/socket.h>
#include <netinet/in.h>

typedef struct adns__state *adns_state;
typedef struct adns__query *adns_query;

typedef enum {
  adns_if_noenv=      0x0001, /* do not look at environment */
  adns_if_noerrprint= 0x0002, /* never print output to stderr */
  adns_if_debug=      0x0004, /* print debugging output to stderr */
  adns_if_noautosys=  0x0008, /* do not do full flow-of-control whenever we can */
} adns_initflags;

typedef enum {
  adns_f_search=     0x0001, /* use the searchlist */
  adns_f_usevc=      0x0002, /* use a virtual circuit (TCP connection) */
  adns_f_anyquote=   0x0004,
} adns_queryflags;

typedef enum {
  adns__rrttype_mask=  0x0fff,
  adns__qtf_deref=     0x1000, /* dereference domains and produce extra data */
  adns__qtf_mailconv=  0x2000, /* put @ between first and second labels */
  adns_r_none=              0,
  adns_r_a=                 1,
  adns_r_ns_raw=            2,
  adns_r_ns=                   adns_r_ns_raw|adns__qtf_deref,
  adns_r_cname=             5,
  adns_r_soa_raw=           6,
  adns_r_soa=                  adns_r_soa_raw|adns__qtf_mailconv,
  adns_r_null=             10,
  adns_r_ptr_raw=          12,
  adns_r_ptr=                  adns_r_ptr_raw|adns__qtf_deref,
  adns_r_hinfo=            13,  
  adns_r_mx_raw=           15,
  adns_r_mx=                   adns_r_mx_raw|adns__qtf_deref,
  adns_r_txt=              16,
  adns_r_rp_raw=           17,
  adns_r_rp=                   adns_r_rp_raw|adns__qtf_mailconv
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
 * Do not ask for records containing mailboxes without
 * specifying qtf_mailconv or qtf_anyquote.
 */

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
 * used.
 */

typedef struct {
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
} adns_answer;

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
 *  If no (appropriate) requests are done adns_check returns EWOULDBLOCK;
 *  If no (appropriate) requests are outstanding adns_query and adns_wait return ESRCH;
 *  If malloc failure occurs during internal allocation or processing
 *  ands_check and _wait set *answer to 0.
 */

int adns_init(adns_state *newstate_r, adns_initflags flags);

int adns_synchronous(adns_state ads,
		     const char *owner,
		     adns_rrtype type,
		     adns_queryflags flags,
		     adns_answer *answer);
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
	       adns_answer *answer,
	       void *context_r);

int adns_wait(adns_state ads,
	      adns_query *query_io,
	      adns_answer *answer,
	      void *context_r);
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

#endif
