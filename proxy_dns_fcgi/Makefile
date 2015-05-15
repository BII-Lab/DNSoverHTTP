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

ALL= proxy_dns_fcgi

all: $(ALL)

clean:
	rm -f $(ALL)
	rm -f *.o

proxy_dns_fcgi: proxy_dns_fcgi.o Makefile
	cc $(LDFLAGS) -pthread -o proxy_dns_fcgi proxy_dns_fcgi.o \
		-lfcgi $(RESOLV) -lpthread

proxy_dns_fcgi.o: proxy_dns_fcgi.c Makefile
	cc $(CFLAGS) -pthread -c proxy_dns_fcgi.c
