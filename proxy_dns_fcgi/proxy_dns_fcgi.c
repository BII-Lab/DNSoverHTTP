/* proxy_dns_fcgi - gateway from FastCGI to DNS
 * 2015-03-13 Paul Vixie [original]
 */

/* Known defects:
 *	Forks threads for parallelism, which is too limited. Needs "libevent".
 */

/* Externals. */

#define _GNU_SOURCE

#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/nameser.h>

#include <assert.h>
#include <errno.h>
#include <fcgiapp.h>
#include <pthread.h>
#include <resolv.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Private data structures. */

#define N_THREADS 4

/*
 * Values for role component of FCGI_BeginRequestBody (from www.fastcgi.com)
 */
#define FCGI_RESPONDER  1
#define FCGI_AUTHORIZER 2
#define FCGI_FILTER     3

typedef struct ctx {
	int fcgi_fd;
} *ctx_t;

static const char sockpath[] = "/tmp/proxy_dns_fcgi.sock";

/* Forward. */

static void *start_fcgi_worker(void *uap);

/* Public. */

int
main(void) {
	pthread_t threads[N_THREADS];
	struct ctx info;
	int fcgifd, i;

	fcgifd = FCGX_OpenSocket(sockpath, 128);
	if (fcgifd < 0) {
		perror("Error opening socket\n");
		exit(1);
	}
	info.fcgi_fd = fcgifd;
	chmod(sockpath, 0777);

	for (i = 0; i < N_THREADS; i++)
		pthread_create(&threads[i], NULL, start_fcgi_worker,
			       (void *) &info);

	for (i = 0; i < N_THREADS; i++)
		pthread_join(threads[i], NULL);

	return (0);
}

void *
start_fcgi_worker(void *uap) {
	ctx_t info = (ctx_t) uap;
	struct __res_state res;
	FCGX_Request request;

	memset(&res, 0, sizeof res);
	(void) res_ninit(&res);
	FCGX_Init();
	FCGX_InitRequest(&request, info->fcgi_fd, 0);

	/* Repeat until killed. */
	for (;;) {
		u_char dnsreq[NS_MAXMSG], dnsresp[NS_MAXMSG];
		const char *method, *len_str, *transport;
		int reqlen, resplen;
		char *errmsg = NULL;
		int status = 0;

		FCGX_Accept_r(&request);
		method = FCGX_GetParam("REQUEST_METHOD", request.envp);
		len_str = FCGX_GetParam("CONTENT_LENGTH", request.envp);
		transport = FCGX_GetParam("HTTP_PROXY_DNS_TRANSPORT",
					  request.envp);
		reqlen = atoi((len_str != NULL) ? len_str : "0");

		/*fprintf(stderr, "request (%d bytes, transport %s)\n",
			reqlen, transport);*/

		if (request.role != FCGI_RESPONDER) {
			asprintf(&errmsg, "bad role = %d\r\n",
				 request.role);
			status = 500;
			goto fini;
		}
		/* GET means display the environment in text. */
		if (method != NULL && strcasecmp(method, "GET") == 0) {
			FCGX_ParamArray p;

			FCGX_PutStr("Content-type: text/plain\r\n\r\n",
				    28, request.out);
			for (p = request.envp;
			     *p != NULL;
			     p++)
				FCGX_FPrintF(request.out,
					     "env '%s'\r\n", *p);
			FCGX_PutStr("EOM\r\n", 5, request.out);
			goto fini;
		}
		/* Otherwise must be a POST with good size. */
		if (strcasecmp(method, "POST") != 0 ||
		    reqlen < NS_HFIXEDSZ ||
		    (size_t)reqlen > sizeof dnsreq ||
		    FCGX_GetStr((char *)dnsreq, reqlen,
				request.in) < reqlen)
		{
			asprintf(&errmsg, "bad reqlen = %d\r\n",
				 reqlen);
			status = 400;
			goto fini;
		}
		/* Our transport must be the same as remote's. */
		if (transport != NULL &&
		    strcasecmp(transport, "TCP") == 0)
			res.options |= RES_USEVC;
		else if (transport != NULL &&
			 strcasecmp(transport, "UDP") == 0)
			res.options &= ~RES_USEVC;
		else {
			asprintf(&errmsg, "bad transport %s\r\n",
				 transport == NULL ? "Null"
				 : transport);
			status = 400;
			goto fini;
		}
		/* Finally, send this query to our system's RDNS. */
		resplen = res_nsend(&res, dnsreq, reqlen,
				    dnsresp, sizeof dnsresp);
		if (resplen < 0) {
			asprintf(&errmsg, "send failed: %s\r\n",
				 strerror(errno));
			status = 503;
			goto fini;
		}
		/* Send RDNS response to remote, unmodified. */
		if (FCGX_PutStr("Status: 200 OK\r\n", 16, request.out) < 0 ||
		    FCGX_PutStr(
		     "Content-type: application/octet-stream\r\n\r\n",
				42, request.out) < 0 ||
		    FCGX_PutStr((char *)dnsresp, resplen,
				request.out) < 0)
		{
			status = 500;
			goto fini;
		}
 fini:
		assert((errmsg != NULL) == (status != 0));
		if (errmsg != NULL) {
			char *msg;

			fprintf(stderr, "%d: %s", status, errmsg);
			asprintf(&msg, "Status: %d %s\r\n", status, errmsg);
			FCGX_PutStr(msg, strlen(msg), request.out);
			FCGX_PutStr("Content-Type: text/plain\r\n\r\n",
				    28, request.out);
			FCGX_PutStr(errmsg, strlen(errmsg), request.out);
			free(errmsg);
			errmsg = NULL;
		}
		FCGX_Finish_r(&request);
	}
	return (NULL);
}
