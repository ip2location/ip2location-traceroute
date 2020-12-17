#include "trace.h"

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

static void print_usage()
{
	printf(
"Usage:\n"
"  ip2trace -p [IP ADDRESS/HOSTNAME] -d [IP2LOCATION BIN DATA PATH] [OPTIONS]\n\n"
"  -d, --database\n"
"  Specify the path of IP2Location BIN database file.\n"
"\n"
"  -h, -?, --help\n"
"  Display this guide.\n"
"\n"
"  -p, --ip\n"
"  Specify an IP address or hostname.\n"
"\n"
"  -t, --ttl\n"
"  Set the max number of hops. (Default: 30)\n"
"\n"
"  -v, --version\n"
"  Print the version of the IP2Location version.\n");
}

static void print_version()
{
	printf(
"IP2Location Geolocation Traceroute (ip2trace) Version 8.0.0\n"
"Copyright (c) 2021 IP2Location.com [MIT License]\n"
"https://www.ip2location.com/free/traceroute-application\n");
}

static int isIpv4(char *ip)
{
	struct sockaddr_in sa;
	return inet_pton(AF_INET, ip, &sa.sin_addr);
}

static int isIpv6(char *ip)
{
	struct in6_addr result;
	return inet_pton(AF_INET6, ip, &result);
}

int main(int argc, char *argv[])
{
	int i;
	int ttl = 30;
	char *database = NULL;
	char ip[INET6_ADDRSTRLEN];
	struct addrinfo buffer, *res;

	for (i = 1; i < argc; i++) {
		const char *argvi = argv[i];

		if (strcmp(argvi, "-d") == 0 || strcmp(argvi, "--database") == 0) {
			if (i + 1 < argc) {
				database = argv[++i];
			}
		} else if (strcmp(argvi, "-p") == 0 || strcmp(argvi, "--ip") == 0) {
			if (i + 1 < argc) {
				int err;
				void *addr;
				struct sockaddr_in *ipv4;
				struct sockaddr_in6 *ipv6;

				memset(&buffer, 0, sizeof buffer);
				buffer.ai_family = AF_UNSPEC;
				buffer.ai_socktype = SOCK_STREAM;

				err = getaddrinfo(argv[++i], "http", &buffer, &res);
				
				if (err != 0) {
					fprintf(stderr, "Host not reachable.\n");
					return EXIT_FAILURE;
				}
				
				// IPv4
				if (res->ai_family == AF_INET) {
					ipv4 = (struct sockaddr_in *)res->ai_addr;
					addr = &(ipv4->sin_addr);
				
				// IPv6
				} else {
					ipv6 = (struct sockaddr_in6 *)res->ai_addr;
					addr = &(ipv6->sin6_addr);
				}

				inet_ntop(res->ai_family, addr, ip, sizeof ip);
				
				// printf("=> %s\n", ip);
				
				freeaddrinfo(res);
			}
		} else if (strcmp(argvi, "-t") == 0 || strcmp(argvi, "--ttl") == 0) {
			if (i + 1 < argc) {
				ttl = atoi(argv[++i]);
			}
		} else if (strcmp(argvi, "-h") == 0 || strcmp(argvi, "-?") == 0 || strcmp(argvi, "--help") == 0) {
			print_usage();
			return 0;
		} else if (strcmp(argvi, "-v") == 0 || strcmp(argvi, "--version") == 0) {
			print_version();
			return 0;
		}
	}

	if (ip == NULL) {
		fprintf(stderr, "Please provide an IP or hostname.\n");
		return EXIT_FAILURE;
	}

	printf(
"IP2Location Geolocation Traceroute (ip2trace) Version 8.0.0\n"
"Copyright (c) 2021 IP2Location.com [MIT License]\n"
"https://www.ip2location.com/free/traceroute-application\n\n");

	if (isIpv4((char *)ip)) {
		trace((char *)ip, (char *)database, 3, ttl);
	} else {
		trace6((char *)ip, (char *)database, 3, ttl);
	}

	return EXIT_SUCCESS;
}
