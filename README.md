Introduction
------------

This is proxy_dns, a way to tunnel DNS inside HTTP. It provides two things:

1. a FastCGI endpoint that sits between a web server (we use nginx, but Apache
would also work) and a DNS server (we use BIND, but Unbound would also work.)
2. a DNS proxy server that is the target of an /etc/resolv.conf (on UNIX) or
DHCP "name server" declaration; it resolves DNS by using upstream HTTP.

The great advantage to this approach is that HTTP usually makes it through
even the worst coffee shop or hotel room firewalls, since commerce may be at
stake. We also benefit from HTTP's persistent TCP connection pool concept,
which DNS on TCP/53 does not have. Lastly, HTTPS will work, giving privacy.

This software is as yet unpackaged, but is portable to FreeBSD 10 and Debian 7
and very probably other BSD-similar and Linux-similar systems. This software
is written entirely in C and has been compiled with GCC and Clang with "full
warnings" enabled.

Construction
------------

More or less, do this:

	(cd proxy_dns_gw; make)
	(cd proxy_dns_fcgi; make)

It is possible that the Makefile will need tweaking, since -lresolv is
required on Linux but is both not required and will not work on BSD due
to differences in their "libc" implementations.

Server Installation
-------------------

The proxy_dns_fcgi service currently just follows /etc/resolv.conf, so you
will need a working name server configuration on your web server. The server
should be reachable by UDP and TCP, and you should have a clear ICMP path to
it, as well as full MTU (1500 octets or larger) and the ability to receive
fragmented UDP (to make EDNS0 usable.)

1. place the proxy_dns_fcgi executable somewhere that nginx can reach it.
2. start this executable and look for a /tmp/proxy_dns_fcgi.sock file.
3. edit nginx.conf to contain something equivilent to the following:

        location /proxy_dns {
                root /;
                fastcgi_pass unix:/tmp/proxy_dns_fcgi.sock;
                include fastcgi_params;
        }

   or, edit httpd.conf to contain something equivilent to the following:

        Listen 24.104.150.237:80
        Listen [2001:559:8000::B]:80

        LoadModule proxy_module libexec/apache24/mod_proxy.so
        LoadModule proxy_fcgi_module libexec/apache24/mod_proxy_fcgi.so

        <VirtualHost 24.104.150.237:80 [2001:559:8000::B]:80>  ServerName proxy-dns.tisf.net
          ProxyPass /proxy_dns \
                    unix:/tmp/proxy_dns_fcgi.sock|fcgi://localhost/ \
                    enablereuse=on
        </VirtualHost>

4. reload the configuration of, or restart, your nginx server.
5. test the integration by visiting the /proxy_dns page with a browser.

Client Installation
-------------------

The proxy_dns_gw service must be told what IP address to listen on for DNS
(noting, it will open both a UDP and a TCP listener on that address), so if
you want it to listen on both ::1 and 127.0.0.1, you will have to start two
listeners, by giving proxy_dns_gw two arguments "-l ::1" and "-l 127.0.0.1".

It must also be told where to connect for its DNS proxy service. If your
FastCGI service (see previous section) is running on a web server
proxy-dns.vix.su, then you will have to specify "-s http://proxy-dns.vix.su"
(or "-s https://proxy-dns.vix.su" if you are using TLS to protect your HTTP.)

1. place the proxy_dns_gw executable somewhere that will survive a reboot.
2. start this executable at least once with appropriate "-s" and "-l" options.
3. use "netstat -an" to determine whether it has opened listener sockets.

Testing
-------

Make sure you have a working "dig" command. If you started your client side
dns_proxy service on 127.0.0.1, then you should be able to say:

	dig @127.0.0.1 www.vix.su aaaa

and get a result back. You can watch this simultaneously on the server side
dns_proxy by running a command similar to this:

	tail -f /var/log/nginx-access.log

Protocol
--------

The protocol used by the dns_proxy service is alarmingly simple. There's no
JSON or XML encoding; the DNS query and response are sent as raw binary via
the "libcurl" library on the client side and the "libfcgi" library on the
server side. The URI is always "/proxy_dns", which means, it contains no
parameters. The result is always marked non-cacheable. The request is always
POST. If you send the fcgi server a GET, it will return a human-readable page
showing its web server environment. There is one new HTTP header:

	Proxy-DNS-Transport: xyz

where xyz is either UDP or TCP, which is the client's indication of how it
received the underlying DNS query, and which the server will use when sending
the query to the far-end DNS server. This means if a stub DNS client asks for
TCP, then that's what the far-end DNS server will see, and likewise for UDP.

The proxy service does not interpret the DNS query or response in any way.
It could be DNS, EDNS, or something not yet invented at the time of this
writing. The only requirement is that each request message solicits exactly
one response message. If anything at all goes wrong with the proxy service,
the stub client will hear a DNS SERVFAIL response.

To Do List
----------

This software was written in C in order to be small, self contained, and
portable to Windows and Mac/OS some day. The protocol was designed to be
very simple in order that higher-performing implementations could be
written for high availability production servers. Still, shortcuts were
taken, and should be addressed:

1. threads on the proxy_dns_fcgi side are a problem. should use "libevent".
2. select() on the proxy_dns_gw side is a problem. should use "libcurl" more.

Authors
-------

This software was conceived and drafted by Paul Vixie during WIDE-2015-03,
and is hereby placed into the public domain, and also placed into the care
of BII, a Beijing-based non-profit Internet technology company.

Note that there is a follow-up work using Golang to implement DNS over HTTP, 
Please visit https://github.com/BII-Lab/DNSoverHTTPinGO for more information.
