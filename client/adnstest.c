/**/

#include <stdio.h>
#include <unistd.h>

#include "adns.h"

int main(void) {
  adns_state ads;
  adns_query qu;
  adns_answer *ans;
  int r;

  r= adns_init(&ads,adns_if_debug|adns_if_noautosys,0);
  if (r) { perror("init"); exit(2); }

  r= adns_submit(ads,"anarres.greenend.org.uk",adns_r_a,0,0,&qu);
  if (r) { perror("submit"); exit(2); }

  r= adns_wait(ads,&qu,&ans,0);
  if (r) { perror("wait"); exit(2); }

  if (!ans) { fputs("no answer\n",stderr); exit(2); }
  fprintf(stderr,"answer status %d type %d rrs %d cname %s\n",
	  ans->status,ans->type,ans->nrrs,
	  ans->cname ? ans->cname : "-");
  
  exit(0);
}
