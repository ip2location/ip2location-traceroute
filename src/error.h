#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <assert.h>
#include <sys/select.h>
#include <sys/time.h>

void Inet_pton(int __af, const char *__restrict__ __cp, void *__restrict__ __buf);
void Inet_ntop(int __af, const void *__restrict__ __cp, char *__restrict__ __buf, socklen_t __len);
int Socket(int __domain, int __type, int __protocol);
void Sendto(int __fd, const void *__buf, size_t __n, int __flags, const struct sockaddr *__addr, socklen_t __addr_len);
void Setsockopt(int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen);
int Select(int __nfds, fd_set *__restrict__ __readfds, fd_set *__restrict__ __writefds, fd_set *__restrict__ __exceptfds, struct timeval *__restrict__ __timeout);
ssize_t Recvfrom(int __fd, void *__restrict__ __buf, size_t __n, int __flags, struct sockaddr *__restrict__ __addr, socklen_t *__restrict__ __addr_len);
void Close(int fd);