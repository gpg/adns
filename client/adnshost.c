/*
 * adnshost.c
 * - useful general-purpose resolver client program
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

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "config.h"

static void sysfail(const char *what, int errnoval) NONRETURNING;
static void sysfail(const char *what, int errnoval) {
  fprintf(stderr,"adnshost failed: %s: %s\n",what,strerror(errnoval));
  exit(10);
}


static void printusage(void) {
  if (fputs
("usage: adnshost [global-opts] [query-opts] query-domain\n"
 "                             [[query-opts] query-domain ...]\n"
 "       adnshost [global-opts] [query-opts] -f|--pipe\n"
 "\n"
 "global binary options:\n"
 "  +e  --no-env         Do not look at environment variables at all.\n"
 "  -f  --pipe           Read queries on stdin instead of using args.\n"
 "  -a  --asynch         Allow answers to be reordered.\n"
 "  -0  --null           stdin items are delimited by nulls.\n"
 "global verbosity level:\n"
 "  -Vq  --quiet         Do not print anything to stderr.\n"
 "  -Vn  --no-quiet      Report unexpected kinds of problem only.  (default)\n"
 "  -Vd  --debug         Debugging mode.\n"
 "other global options:\n"
 "  --help, --version    Print usage or version information.\n"
 "\n"
 "per-query binary options:\n"
 "  -s   --search        Use the search list.\n"
 "  -Qq  --qc-query      Let query domains contain quote-requiring chars.\n"
 "  -Qa  --qc-anshost    Let hostnames in answers contain ...\n"
 "  +Qc  --no-qc-cname   Prevent CNAME target domains from  containing ...\n"
 "  -u   --tcp           Force use of a virtual circuit.\n"
 "  +Do  --no-owner      Do not display owner name in output.\n"
 "  +Dt  --no-type       Do not display RR type in output.\n"
 "  +Dc  --no-show-cname Do not display CNAME target in output.\n"
 "per-query TTL mode (NB TTL is minimum across whole query reply):\n"
 "  -Tt  --ttl-ttl       Show the TTL as a TTL.\n"
 "  -Ta  --ttl-abs       Show the TTL as a time_t when the data might expire.\n"
 "  -Tn  --no-ttl        Do not show the TTL (default).\n"
 "per-query cname handling mode:\n"
 "  -Cf  --cname-reject  Call it an error if a CNAME is found.\n"
 "  -Cl  --cname-loose   Allow references to CNAMEs in other RRs.\n"
 "  -Cs  --cname-ok      CNAME ok for query domain, but not in RRs (default).\n"
 "query type:\n"
 "  -t<type>           } Set the query type (see below).\n"
 "  --type <type>      }  Default is addr.  Not case-sensitive.\n"
 "other per-query options:\n"
 "  -i<id>             } Set the <id> to print in the output with --async;\n"
 "  --asynch-id <id>   }  default is a sequence number in decimal starting at 0.\n"
 "  --cancel-id <id>     Cancel the query with id <id>.\n"
 "  - <domain>           Next argument is a domain, but more options may follow.\n"
 "\n"
 "For binary options, --FOO and --no-FOO are opposites, as are\n"
 "-X and +X.  In each case the default is the one not listed.\n"
 "Per query options stay set a particular way until they are reset,\n"
 "whether they appear on the command line or on stdin.\n"
 "All global options must preceed the first query domain.\n"
 "\n"
 "Output format is master file format without class or TTL by default:\n"
 " [<owner>] [<ttl>] [<type>] <data>\n"
 "or if the <owner> domain refers to a CNAME and --show-cname is on\n"
 " [<owner>] [<ttl>] CNAME <cname>\n"
 " [<cname>] [<ttl>] <type> <data>\n"
 "When a query fails you get a line like:\n"
 " ; failed <statustype> [<owner>] [<ttl>] [<type>] <status> \"<status string>\"\n"
 "If you use --asynch, you don't get that.  Instead, each answer (success or\n"
 "failure) is preceded by a line:\n"
 " <id> <statustype> <status> <nrrs> [<cname>] \"<status string>\"\n"
 "where <nrrs> is the number of RRs that follow and <cname> will be `$' or\n"
 "the canonical name.\n"
 "\n"
 "With -f, the input should be a list of arguments one per line (ie separated\n"
 "by newlines), or separated by null characters if -0 or --null was used\n"
 "\n"
 "Exit status:\n"
 " 0    all went well\n"
 " 1-6  at least one query failed with statustype:\n"
 "   1    localfail   )\n"
 "   2    remotefail  ) temporary errors\n"
 "   3    tempfail  __)_________________\n"
 "   4    misconfig   )\n"
 "   5    misquery    ) permanent errors\n"
 "   6    permfail    )\n"
 " 10   system trouble\n"
 " 11   usage problems\n"
 "\n"
 "Query types (see adns.h):\n"
 "  ns  soa  ptr  mx  rp  addr       - enhanced versions\n"
 "  cname  hinfo  txt                - types with only one version\n"
 "  a  ns-  soa-  ptr-  mx-  rp-     - _raw versions\n",
 stdout) == EOF) sysfail("write usage message",errno);
}

int main(int argc, const char *const *argv) {
  printusage();
  if (fclose(stdout)) sysfail("finish writing output",errno);
  exit(0);
}
