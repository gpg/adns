CC=gcc $(WARNS) $(WERROR) $(OPTIMISE) $(DEBUG)
DEBUG=-g
OPTIMISE=-O2
WARNS=	-Wall -Wmissing-prototypes -Wwrite-strings -Wstrict-prototypes \
	-Wcast-qual -Wpointer-arith
WERROR=-Werror

all:		dtest

dtest:		dtest.o adns.o
