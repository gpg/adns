/**/

#include <stdio.h>

#include "adns.h"

int main(void) {
  adns_state ads;
  int r;

  r= adns_init(&ads,adns_if_debug);
  if (r) { perror("init"); exit(2); }
  exit(0);
}
