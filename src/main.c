#include "trace.h"
#include "error.h"
#include <netdb.h> 

static void print_usage()
{
	printf(
"Usage:\n"
"  ipltrace -p [IP ADDRESS/HOSTNAME] -d [IP2LOCATION BIN DATA PATH] [OPTIONS]\n\n"
"  -d, --dababase\n"
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
	printf("IP2Location Traceroute 8.0.0\n");
}

int main(int argc, char *argv[])
{
	int i;
	int ttl = 30;
	char *database = NULL;
	const char *ip = NULL;
	struct hostent *host_entry;

	for (i = 1; i < argc; i++) {
		const char *argvi = argv[i];

		if (strcmp(argvi, "-d") == 0 || strcmp(argvi, "--database") == 0) {
			if (i + 1 < argc) {
				database = argv[++i];
			}
		} else if (strcmp(argvi, "-p") == 0 || strcmp(argvi, "--ip") == 0) {
			if (i + 1 < argc) {
				host_entry = gethostbyname(argv[++i]);
				ip = inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0]));
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

	trace((char *)ip, (char *)database, 3, ttl);

	return EXIT_SUCCESS;
}
