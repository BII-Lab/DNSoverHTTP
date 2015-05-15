/* External. */

#define _GNU_SOURCE

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>

/* Parameters. */

#define	DEBUGGING_OUTPUT 1
#define	TCP_DNS_TIMEOUT 3

/* Private. */

typedef union sockaddr_union {
	struct sockaddr_in6 sa6;
	struct sockaddr_in sa4;
	struct sockaddr sa;
} *sockaddr_union_t;

typedef struct upstream {
	int socket;
	union sockaddr_union from;
	socklen_t fromlen;
	struct curl_slist *headers;
	char *url, *transport;
	u_char *dnsreq, *resp;
	size_t reqlen, resplen;
	char errorbuffer[CURL_ERROR_SIZE];
} *upstream_t;

typedef struct timeout {
	struct timeout *next;
	time_t when;
	int socket;
} *timeout_t;

typedef struct listener {
	struct listener *next;
	int udp, tcp;
} *listener_t;

enum conntype { e_none, e_udp, e_tcp };

static listener_t listeners = NULL;
static int ourmax = -1;
static int ncurl = 0, debug = 0;
static timeout_t timeouts = NULL;
static const char *server = NULL;
static fd_set ourfds;

#if DEBUGGING_OUTPUT
#define DPRINTF(l, x) if (debug >= l) fprintf x; else {}
#else
#define DPRINTF(l, x) 0
#endif

/* Forward. */

static void upstream_complete(upstream_t arg);
static void udp_input(CURLM *, int fd);
static void tcp_session(int listener);
static void tcp_input(CURLM *, int fd);
static void tcp_close(int fd);
static int launch_request(CURLM *, const u_char *, size_t,
			  int, const char *, union sockaddr_union, socklen_t);
static size_t write_callback(char *ptr, size_t size, size_t count,
			     void *userdata);
static listener_t get_sockets(const char *, int default_port);
static enum conntype our_listener_p(int fd);
static int get_sockaddr(const char *, int, sockaddr_union_t,
			socklen_t *, int *);
static int add_timeout(time_t when, int socket);
static void update_timeout(time_t when, int socket);
static int remove_timeout(int socket);
static long do_timeouts(time_t as_of);
static upstream_t upstream_create(int, union sockaddr_union, socklen_t,
				  const u_char *, size_t);
static void upstream_destroy(upstream_t *arg);
static void debug_dump(int level, const char *after);
#if DEBUGGING_OUTPUT
static char *fdlist(int, fd_set *);
#endif

/* Public. */

int
main(int argc, char **argv) {
	listener_t listener;
	CURLM *curlm;
	int ch;

	while ((ch = getopt(argc, argv, "dl:s:")) != -1) {
		switch (ch) {
		case 'd':
			debug++;
			break;
		case 'l':
			listener = get_sockets(optarg, NS_DEFAULTPORT);
			if (listener == NULL) {
				perror("get_sockets");
				exit(1);
			}
			listener->next = listeners;
			listeners = listener;
			listener = NULL;
			break;
		case 's':
			if (server != NULL) {
				fprintf(stderr, "-s may only appear once\n");
				exit(1);
			}
			server = strdup(optarg);
			break;
		default:
			fprintf(stderr,
				"usage: proxy_dns_gw "
				"-l addr[,port] "
				"-s server"
				"\n");
			exit(1);
		}
	}
	argc -= optind, argv += optind;

	if (listeners == NULL) {
		fprintf(stderr, "-l must be specified\n");
		exit(1);
	}
	if (server == NULL) {
		fprintf(stderr, "-s must be specified\n");
		exit(1);
	}

	FD_ZERO(&ourfds);
	ourmax = -1;
	for (listener = listeners; listener != NULL; listener = listener->next)
	{
		fcntl(listener->tcp, F_SETFL,
		      fcntl(listener->tcp, F_GETFL) | O_NONBLOCK);
		fcntl(listener->udp, F_SETFL,
		      fcntl(listener->udp, F_GETFL) | O_NONBLOCK);
		listen(listener->tcp, 10);
		FD_SET(listener->udp, &ourfds);
		FD_SET(listener->tcp, &ourfds);
		ourmax = MAX(ourmax, MAX(listener->udp, listener->tcp));
	}

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curlm = curl_multi_init();
	for (;;) {
		long curl_timeout, our_timeout;
		fd_set input, output, except;
		int maxfd, curl_maxfd, n;
		struct timeval to, *top;
		struct CURLMsg *msg;

		input = ourfds;
		FD_ZERO(&output);
		FD_ZERO(&except);

		/* Find highest FD among our listeners, sessions, and curl. */
		curl_multi_fdset(curlm, &input, &output, &except, &curl_maxfd);
		maxfd = MAX(curl_maxfd, ourmax);

		/* Timeout is ours or curl's, whichever is sooner. */
		curl_multi_timeout(curlm, &curl_timeout);

		/* "Note:  if libcurl returns a -1 timeout here, it just means
		 * that libcurl currently has no stored timeout value. You
		 * must not wait too long (more * than a few seconds perhaps)
		 * before you call curl_multi_perform() again."
		 *
		 * (from curl_multi_timeout(3) as of 2015-03-21)
		 */
#if BOGUS
		if (curl_timeout < 0L && ncurl > 0)
			curl_timeout = 2500;	/* ms; so, 2.5sec */
#endif
		our_timeout = do_timeouts(time(NULL));
		if (curl_timeout < 0L && our_timeout < 0L) {
			/* Noone has a timeout; wait until input. */
			top = NULL;
		} else {
			long timeout;

			if (curl_timeout < 0L)
				timeout = our_timeout;
			else if (our_timeout < 0L)
				timeout = curl_timeout;
			else
				timeout = MIN(our_timeout, curl_timeout);

			top = &to;
			to.tv_sec = timeout / 1000;
			to.tv_usec = (timeout % 1000) * 1000;
		}
#if DEBUGGING_OUTPUT
		if (debug >= 1) {
			char *in = fdlist(maxfd + 1, &input),
				*out = fdlist(maxfd + 1, &output),
				*exc = fdlist(maxfd + 1, &except),
				*tim = NULL;

			if (top == NULL)
				tim = strdup("Nil");
			else
				asprintf(&tim, "%lu.%06lu",
					 (u_long) top->tv_sec,
					 (u_long) top->tv_usec);

			fprintf(stderr, "select(%d, %s, %s, %s, %s)\n",
				maxfd + 1, in, out, exc, tim);
			free(in);
			free(out);
			free(exc);
			free(tim);
		}
#endif
		n = select(maxfd + 1, &input, &output, &except, top);
		if (n < 0) {
			perror("select");
			exit(1);
		}
		DPRINTF(2, (stderr, "select = %d\n", n));
		curl_multi_perform(curlm, &n);
		while ((msg = curl_multi_info_read(curlm, &n)) != NULL) {
			if (msg->msg == CURLMSG_DONE) {
				upstream_t arg;
				long rcode;

				assert(curl_easy_getinfo(msg->easy_handle,
							 CURLINFO_PRIVATE,
							 (char *) &arg)
				       == CURLE_OK);
				assert(curl_easy_getinfo(msg->easy_handle,
							 CURLINFO_RESPONSE_CODE,
							 (char *) &rcode)
				       == CURLE_OK);
				curl_multi_remove_handle(curlm, msg->
							 easy_handle);
#if DEBUGGING_OUTPUT
				if (msg->data.result != CURLE_OK) {
					fprintf(stderr, "error: '%s'\n",
						arg->errorbuffer);
				}
#endif
				if (rcode != 200) {
					fprintf(stderr, "failure, code %d:\n"
							"---\n%-*.*s===\n",
						(int) rcode,
						(int) arg->resplen,
						(int) arg->resplen,
						arg->resp);
					free(arg->resp);
					arg->resp = NULL;
					arg->resplen = 0;
				}
				upstream_complete(arg);
				upstream_destroy(&arg);
				ncurl--;
			} else {
				DPRINTF(1, (stderr, "info_read !done (%d)\n",
					msg->data.result));
			}
		}

		for (n = 0; n <= ourmax; n++) {
			if (FD_ISSET(n, &ourfds) && FD_ISSET(n, &input)) {
				if (our_listener_p(n) == e_udp)
					udp_input(curlm, n);
				else if (our_listener_p(n) == e_tcp)
					tcp_session(n);
				else
					tcp_input(curlm, n);
			}
		}
	}
	curl_multi_cleanup(curlm);
	return (EXIT_SUCCESS);
}

/* Private. */

static void
upstream_complete(upstream_t arg) {
	enum conntype ct;
	int n;

	assert(arg != NULL);
	assert((arg->resp != NULL) == (arg->resplen != 0));

	DPRINTF(2, (stderr, "upstream_complete(%p, %d, %s)\n",
		    arg, arg->socket, arg->url));

	/* Calling us with nothing in the output buffer means SERVFAIL. */
	if (arg->resp == NULL) {
		arg->resp = arg->dnsreq;
		arg->resplen = arg->reqlen;
		((HEADER *)arg->resp)->rcode = SERVFAIL;
		((HEADER *)arg->resp)->qr = 1;
		((HEADER *)arg->resp)->ra = 1;
		arg->dnsreq = NULL;
		arg->reqlen = 0;
	}

	ct = our_listener_p(arg->socket);
	if (ct == e_udp) {
		n = sendto(arg->socket, arg->resp, arg->resplen,
			   0, &arg->from.sa, arg->fromlen);
	} else if (ct == e_none) {
		struct iovec iov[2];
		struct msghdr msg;
		u_char msglen[2];

		ns_put16(arg->resplen, msglen);
		memset(&msg, 0, sizeof msg);
		msg.msg_name = &arg->from;
		msg.msg_namelen = arg->fromlen;
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;
		iov[0].iov_base = msglen;
		iov[0].iov_len = sizeof msglen;
		iov[1].iov_base = arg->resp;
		iov[1].iov_len = arg->resplen;

		n = sendmsg(arg->socket, &msg, 0);
	} else {
		abort();
	}
	if (n < 0)
		perror("send");
}

static void
udp_input(CURLM *curlm, int fd) {
	union sockaddr_union from;
	u_char dnsreq[NS_MAXMSG];
	socklen_t fromlen;
	ssize_t reqlen;
		    
	DPRINTF(1, (stderr, "udp_input(%d)\n", fd));

	while (fromlen = sizeof from,
	       (reqlen = recvfrom(fd, dnsreq, sizeof dnsreq, 0,
				  &from.sa, &fromlen)) > 0)
	{
		(void) launch_request(curlm, dnsreq, reqlen,
				      fd, "UDP", from, fromlen);
	}
}

static void
tcp_session(int listener) {
	struct sockaddr from;
	socklen_t fromlen;
	int tcp_client;

	fromlen = sizeof from;
	tcp_client = accept(listener, &from, &fromlen);
	if (tcp_client < 0) {
		perror("accept");
		return;
	}
	assert(!FD_ISSET(tcp_client, &ourfds));
	FD_SET(tcp_client, &ourfds);
	if (tcp_client > ourmax)
		ourmax = tcp_client;

	DPRINTF(1, (stderr, "tcp_session(%d -> %d)\n", listener, tcp_client));

	fcntl(tcp_client, F_SETFL,
	      fcntl(tcp_client, F_GETFL) | O_NONBLOCK);

	if (add_timeout(time(NULL) + TCP_DNS_TIMEOUT, tcp_client) < 0) {
		perror("add_timeout");
		tcp_close(tcp_client);
		return;
	}
	debug_dump(2, "tcp_session");
}

static void
tcp_input(CURLM *curlm, int tcp_client) {
	u_char reqlen[NS_INT16SZ], req[NS_MAXMSG];
	union sockaddr_union from;
	socklen_t fromlen;
	int len1, len2;

	len1 = read(tcp_client, reqlen, sizeof reqlen);
	if (len1 == 0) {
		tcp_close(tcp_client);
		remove_timeout(tcp_client);
		return;
	}
	if (len1 < 0) {
		fprintf(stderr, "read(tcp_client #1): %s\n",
			strerror(errno));
		goto abend;
	}
	if (len1 != sizeof reqlen) {
		fprintf(stderr, "read(tcp_client #1): %d octets\n",
			len1);
		goto abend;
	}
	len1 = ns_get16(reqlen);

	DPRINTF(1, (stderr, "tcp_input(%d -> %d)\n",
		    tcp_client, len1));

	len2 = read(tcp_client, req, sizeof req);
	if (len2 < 0) {
		fprintf(stderr, "read(tcp_client #2): %s\n",
			strerror(errno));
		goto abend;
	}
	if (len2 != len1) {
		fprintf(stderr, "read(tcp_client #2): %d (vs %d)\n",
			len1, len2);
		goto abend;
	}
	fromlen = sizeof from;
	if (getpeername(tcp_client, &from.sa, &fromlen) < 0) {
		fprintf(stderr, "getpeername(tcp_client): %s\n",
			strerror(errno));
		goto abend;
	}
	if (launch_request(curlm, req, len2, tcp_client,
			   "TCP", from, fromlen) < 0)
		goto abend;

	update_timeout(time(NULL) + TCP_DNS_TIMEOUT, tcp_client);
	debug_dump(2, "tcp_input#1");
	return;

 abend:
	tcp_close(tcp_client);
	remove_timeout(tcp_client);
	debug_dump(2, "tcp_input#2");
}

static void
tcp_close(int fd) {
	assert(FD_ISSET(fd, &ourfds));
	if (fd == ourmax) {
		FD_CLR(ourmax, &ourfds);
		do {
			ourmax--;
		} while (ourmax > 0 && !FD_ISSET(ourmax, &ourfds));
	}
	DPRINTF(2, (stderr, "tcp_close(%d), outmax is now %d\n", fd, ourmax));
	close(fd);
	debug_dump(2, "tcp_close");
}

static int
launch_request(CURLM *curlm, const u_char *dnsreq, size_t reqlen,
	       int outputsock, const char *transport,
	       union sockaddr_union from, socklen_t fromlen)
{
	upstream_t arg = NULL;
	CURL *curl = NULL;
	CURLMcode res;
	int x;

	arg = upstream_create(outputsock, from, fromlen, dnsreq, reqlen);
	if (arg == NULL) {
		fprintf(stderr, "upstream_create failed\n");
		return (-1);
	}

	curl = curl_easy_init();
	if (curl == NULL) {
		fprintf(stderr, "curl_easy_init failed\n");
		goto servfail;
	}

	x = asprintf(&arg->url, "%s/proxy_dns", server);
	if (x < 0) {
		perror("asprintf");
		goto servfail;
	}

	x = asprintf(&arg->transport, "Proxy-DNS-Transport: %s", transport);
	if (x < 0) {
		perror("asprintf #2");
		goto servfail;
	}

	curl_easy_setopt(curl, CURLOPT_PRIVATE, arg);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, arg->errorbuffer);
	curl_easy_setopt(curl, CURLOPT_URL, arg->url);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	arg->headers = curl_slist_append(arg->headers, "Accept: "
					 "application/octet-stream");
	arg->headers = curl_slist_append(arg->headers, "Content-Type: "
					 "application/octet-stream");
	arg->headers = curl_slist_append(arg->headers, arg->transport);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, arg->headers);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, dnsreq);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, reqlen);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (char *)arg);

	res = curl_multi_add_handle(curlm, curl);
	if (res != CURLM_OK) {
		fprintf(stderr, "curl_multi_add_handle() failed: %s\n",
			curl_multi_strerror(res));
		goto servfail;
	}

	ncurl++;
	DPRINTF(2, (stderr, "launch_request: ncurl %d, arg %p, easy %p\n",
		    ncurl, arg, curl));
	return (0);

 servfail:
	if (curl != NULL) {
		curl_easy_cleanup(curl);
		curl = NULL;
	}

	upstream_complete(arg);
	upstream_destroy(&arg);
	return (-1);
}

static size_t
write_callback(char *ptr, size_t size, size_t count, void *userdata) {
	upstream_t arg = userdata;
	size_t len = size * count;

	arg->resp = realloc(arg->resp, arg->resplen + len);
	memcpy(arg->resp + arg->resplen, ptr, len);
	arg->resplen += len;
	return (len);
}	

static listener_t
get_sockets(const char *spec, int default_port) {
	union sockaddr_union su;
	listener_t new;
	char *p, *addr;
	socklen_t len;
	int udp, tcp, pf, port;
	const int on = 1;

	if ((p = strchr(spec, '/')) == NULL)
		p = strchr(spec, ',');
	if (p != NULL)
		port = atoi(p + 1);
	else
		port = default_port;
	if (port == 0) {
		fprintf(stderr, "port number '%s' is not valid\n", p + 1);
		return (NULL);
	}
	addr = strndup(spec, p - spec);
	if (!get_sockaddr(addr, port, &su, &len, &pf)) {
		fprintf(stderr, "address '%s' is not valid\n", addr);
		free(addr);
		return (NULL);
	}
	free(addr);

	udp = socket(pf, SOCK_DGRAM, 0);
	if (udp == -1) {
		perror("socket(udp)");
		return (NULL);
	}
	if (bind(udp, &su.sa, len) == -1) {
		perror("bind(udp)");
		close(udp);
		return (NULL);
	}
	tcp = socket(pf, SOCK_STREAM, 0);
	if (tcp == -1) {
		perror("socket(tcp)");
		close(udp);
		close(tcp);
		return (NULL);
	}
#ifdef SO_REUSEADDR
	(void) setsockopt(tcp, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
#endif
#ifdef SO_REUSEPORT
	(void) setsockopt(tcp, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
#endif
	if (bind(tcp, &su.sa, len) == -1) {
		perror("bind(tcp)");
		close(udp);
		close(tcp);
		return (NULL);
	}
	new = malloc(sizeof *new);
	if (new == NULL) {
		perror("malloc");
		close(udp);
		close(tcp);
		return (NULL);
	}
	memset(new, 0, sizeof *new);
	new->udp = udp;
	new->tcp = tcp;
	new->next = NULL;
	return (new);
}

static enum conntype
our_listener_p(int fd) {
	listener_t listener;

	for (listener = listeners; listener != NULL; listener = listener->next)
	{
		if (fd == listener->udp)
			return (e_udp);
		if (fd == listener->tcp)
			return (e_tcp);
	}
	return (e_none);
}

static int
get_sockaddr(const char *input, int port,
	     sockaddr_union_t sup, 
	     socklen_t *lenp, int *pfp)
{
	memset(sup, 0, sizeof *sup);
	if (inet_pton(AF_INET6, input, &sup->sa6.sin6_addr) > 0) {
		*lenp = sizeof sup->sa6;
		sup->sa6.sin6_family = AF_INET6;
#ifdef BSD4_4
		sup->sa6.sin6_len = *lenp;
#endif
		sup->sa6.sin6_port = htons(port);
		*pfp = PF_INET6;
	} else if (inet_pton(AF_INET, input, &sup->sa4.sin_addr) > 0) {
		*lenp = sizeof sup->sa4;
		sup->sa4.sin_family = AF_INET;
#ifdef BSD4_4
		sup->sa4.sin_len = *lenp;
#endif
		sup->sa4.sin_port = htons(port);
		*pfp = PF_INET;
	} else {
		return (0);
	}
	return (1);
}

static int
add_timeout(time_t when, int socket) {
	timeout_t new, cur, prev;

	new = malloc(sizeof *new);
	if (new == NULL)
		return (-1);
	new->next = NULL;
	new->when = when;
	new->socket = socket;

	prev = NULL;
	for (cur = timeouts; cur != NULL; cur = cur->next)
		prev = cur;

	if (prev == NULL)
		timeouts = new;
	else
		prev->next = new;

	return (0);
}

static void
update_timeout(time_t when, int socket) {
	timeout_t cur1, cur2, prev1, prev2;

	prev1 = NULL;
	for (cur1 = timeouts; cur1 != NULL; cur1 = cur1->next) {
		if (cur1->socket == socket)
			break;
		prev1 = cur1;
	}
	assert(cur1 != NULL);
	cur1->when = when;

	prev2 = cur1;
	for (cur2 = cur1->next; cur2 != NULL; cur2 = cur2->next) {
		if (cur2->when > cur1->when)
			break;
		prev2 = cur2;
	}
	assert(prev2 != NULL);

	if (cur1->next != cur2) {
		/* Delete. */
		if (prev1 == NULL) {
			assert(timeouts == cur1);
			timeouts = cur1->next;
		} else {
			assert(prev1->next == cur1);
			prev1->next = cur1->next;
		}
		/* Insert. */
		cur1->next = cur2;
		prev2->next = cur1;
	}
}

static int
remove_timeout(int socket) {
	timeout_t cur, prev;

	prev = NULL;
	for (cur = timeouts; cur != NULL; cur = cur->next) {
		if (cur->socket == socket)
			break;
		prev = cur;
	}
	if (cur == NULL)
		return (0);
	if (prev == NULL)
		timeouts = cur->next;
	else
		prev->next = cur->next;
	free(cur);
	return (1);
}

static long
do_timeouts(time_t as_of) {
	while (timeouts != NULL && timeouts->when <= as_of) {
		tcp_close(timeouts->socket);
		remove_timeout(timeouts->socket);
	}
	if (timeouts != NULL)
		return ((as_of - timeouts->when) * 1000);
	return (-1L);
}

static upstream_t
upstream_create(int outputsock,
		union sockaddr_union from, socklen_t fromlen,
		const u_char *dnsreq, size_t reqlen)
{
	upstream_t arg = malloc(sizeof *arg);

	if (arg == NULL) {
		perror("upstream_create: malloc #1");
		return (NULL);
	}
	arg->dnsreq = malloc(reqlen);
	if (arg->dnsreq == NULL) {
		perror("upstream_create: malloc #2");
		free(arg);
		return (NULL);
	}
	memcpy(arg->dnsreq, dnsreq, reqlen);
	arg->reqlen = reqlen;
	arg->socket = outputsock;
	arg->from = from;
	arg->fromlen = fromlen;
	arg->headers = NULL;
	arg->url = NULL;
	arg->resp = NULL;
	arg->resplen = 0;
	return (arg);
}

static void
upstream_destroy(upstream_t *argp) {
	if ((*argp)->headers != NULL) {
		curl_slist_free_all((*argp)->headers);
		(*argp)->headers = NULL;
	}
	if ((*argp)->transport != NULL) {
		free((*argp)->transport);
		(*argp)->transport = NULL;
	}
	if ((*argp)->url != NULL) {
		free((*argp)->url);
		(*argp)->url = NULL;
	}
	if ((*argp)->resp != NULL) {
		free((*argp)->resp);
		(*argp)->resp = NULL;
	}
	free(*argp);
	*argp = NULL;
}

static void
debug_dump(int level, const char *after) {
#if DEBUGGING_OUTPUT
	time_t now = time(NULL);
	timeout_t to;
	int fd;

	if (debug < level)
		return;
	fprintf(stderr, "debug_dump(%s)...\n", after);
	fprintf(stderr, "fd 0..%d:", ourmax);
	for (fd = 0; fd <= ourmax; fd++)
		if (FD_ISSET(fd, &ourfds))
			fprintf(stderr, " %d", fd);
	fputc('\n', stderr);
	fprintf(stderr, "to @%lu:", now);
	for (to = timeouts; to != NULL; to = to->next)
		fprintf(stderr, " %d@%ld", to->socket, now - to->when);
	fputc('\n', stderr);
	fputs("---\n", stderr);
#else
	after++;
#endif
}

static char *
fdlist(int nfds, fd_set *fdset) {
	const char *sep = "";
	char *pres = strdup("["), *tmp;
	int fd;

	for (fd = 0; fd < nfds; fd++)
		if (FD_ISSET(fd, fdset)) {
			asprintf(&tmp, "%s%s%d", pres, sep, fd);
			free(pres);
			pres = tmp;
			tmp = NULL;
			sep = " ";
		}
	asprintf(&tmp, "%s]", pres);
	free(pres);
	pres = tmp;
	tmp = NULL;
	return (pres);
}
