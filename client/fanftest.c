
#include <sys/types.h>
#include <sys/time.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "adns.h"

static const char *progname;

#define msg(fmt, args...) fprintf(stderr, "%s: " fmt "\n", progname, ##args)

static void aargh(const char *cause) {
  const char *why = strerror(errno);
  if (!why) why = "Unknown error";
  msg("%s: %s (%d)", cause, why, errno);
  exit(1);
}

int main(int argc, char *argv[]) {
  adns_state adns;
  adns_query query;
  adns_answer *answer;

  progname= strrchr(*argv, '/');
  if (progname)
    progname++;
  else
    progname= *argv;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <domain>\n", progname);
    exit(1);
  }

  errno= adns_init(&adns, adns_if_debug, 0);
  if (errno) aargh("adns_init");

  errno= adns_submit(adns, argv[1], adns_r_ptr,
		     adns_qf_quoteok_cname|adns_qf_cname_loose,
		     NULL, &query);
  if (errno) aargh("adns_submit");

  errno= adns_wait(adns, &query, &answer, NULL);
  if (errno) aargh("adns_init");

  printf("%s\n", answer->status == adns_s_ok ? *answer->rrs.str : "dunno");

  adns_finish(adns);

  return 0;
}
