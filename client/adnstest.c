/**/

#include <stdio.h>
#include <unistd.h>

#include "adns.h"

int main(void) {
  adns_state ads;
  adns_query qu;
  int r;

  r= adns_init(&ads,adns_if_debug|adns_if_noautosys);
  if (r) { perror("init"); exit(2); }

  r= adns_submit(ads,"anarres.greenend.org.uk",adns_r_a,0,0,&qu);
  if (r) { perror("submit"); exit(2); }
  
  exit(0);
}
