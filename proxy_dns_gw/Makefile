CURLINCL = `curl-config --cflags` 
CURLLIBS = `curl-config --static-libs`

CFLAGS= -I/usr/local/include
LDFLAGS= -L/usr/local/lib
RESOLV= 
#RESOLV= -lresolv 

CWARN =-W -Wall -Wcast-qual -Wpointer-arith -Wwrite-strings \
	-Wmissing-prototypes  -Wbad-function-cast -Wnested-externs \
	-Wunused -Wshadow -Wmissing-noreturn -Wswitch-enum -Wformat-nonliteral
# -Wunreachable-code is often wrong
#CWARN  +=-Wunreachable-code
# try shipping without any warnings
CWARN   +=-Werror

CDEBUG = -g
CFLAGS += $(CDEBUG) $(CWARN)

ALL= proxy_dns_gw

all: $(ALL)

clean:
	rm -f $(ALL)
	rm -f *.o *.core

proxy_dns_gw: proxy_dns_gw.o Makefile
	cc $(LDFLAGS) -o proxy_dns_gw proxy_dns_gw.o \
		$(CURLLIBS) $(RESOLV)

.c.o:
	cc $(CFLAGS) $(CURLINCL) -c $<
