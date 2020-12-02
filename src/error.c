#include "error.h"

void Inet_pton(int __af, const char *__restrict__ __cp, void *__restrict__ __buf)
{
	int is_destination_address_correct = inet_pton(__af, __cp, __buf);
	
	if (is_destination_address_correct != 1) {
		if (is_destination_address_correct == 0) {
			fprintf(stderr, "This is not a valid address\n");
		} else if (is_destination_address_correct == -1) {
			fprintf(stderr, "Invalid address family, error: %s\n", strerror(errno));
		} else {
			fprintf(stderr, "Unknown error\n");
		}

		exit(EXIT_FAILURE);
	}
}

void Inet_ntop(int __af, const void *__restrict__ __cp, char *__restrict__ __buf, socklen_t __len)
{
	char *ptr = (char *)inet_ntop(__af, __cp, __buf, __len);
	
	if (ptr == NULL) {
		fprintf(stderr, "Error in inet_ntop, error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

int Socket(int __domain, int __type, int __protocol)
{
	int sockfd = socket(__domain, __type, __protocol);
	
	if (sockfd == -1) {
		fprintf(stderr, "Error in socket, error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return sockfd;
}
void Sendto(int __fd, const void *__buf, size_t __n, int __flags, const struct sockaddr *__addr, socklen_t __addr_len)
{
	int bytes_sent = sendto(__fd, __buf, __n, __flags, __addr, __addr_len);

	if (bytes_sent == -1) {
		fprintf(stderr, "Error in sendto, error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	} else if (bytes_sent == 0) {
		exit(EXIT_FAILURE);
	}
}

void Setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen)
{
	if (setsockopt(__fd, __level, __optname, __optval, __optlen) == -1) {
		fprintf(stderr, "Error in setsockopt, error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

int Select(int __nfds, fd_set *__restrict__ __readfds, fd_set *__restrict__ __writefds, fd_set *__restrict__ __exceptfds, struct timeval *__restrict__ __timeout)
{
	int n = select(__nfds, __readfds, __writefds, __exceptfds, __timeout);
	
	if (n == -1) {
		fprintf(stderr, "Error in select, error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return n;
}

ssize_t Recvfrom(int __fd, void *__restrict__ __buf, size_t __n, int __flags, struct sockaddr *__restrict__ __addr, socklen_t *__restrict__ __addr_len)
{
	int packet_len = recvfrom(__fd, __buf, __n, __flags, __addr, __addr_len);
	
	if (packet_len == -1 && errno != EWOULDBLOCK) {
		fprintf(stderr, "Error in recvfrom,error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return packet_len;
}

void Close(int fd)
{
	if (close(fd) == -1) {
		fprintf(stderr, "Error in close,error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}
