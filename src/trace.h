#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#if defined(__has_include)
#if __has_include(<netinet/icmp6.h>)
#include <netinet/icmp6.h>
#endif
#else
#include <netinet/icmp6.h>
#endif
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <IP2Location.h>

#if !defined(__linux__)
struct icmphdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	union {
		struct {
			uint16_t id;
			uint16_t sequence;
		} echo;
		uint32_t gateway;
		struct {
			uint16_t unused;
			uint16_t mtu;
		} frag;
	} un;
};
#endif

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif

#ifndef ICMP_DEST_UNREACH
#define ICMP_DEST_UNREACH 3
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

#ifndef ICMP_TIME_EXCEEDED
#define ICMP_TIME_EXCEEDED 11
#endif

#ifndef ICMP6_ECHO_REQUEST
struct icmp6_hdr {
	uint8_t icmp6_type;
	uint8_t icmp6_code;
	uint16_t icmp6_cksum;
	uint16_t icmp6_id;
	uint16_t icmp6_seq;
};
#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY 129
#define ICMP6_DST_UNREACH 1
#define ICMP6_TIME_EXCEEDED 3
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH 135
#endif

struct reply {
	int replied;
	struct sockaddr_in sender;
	struct sockaddr_in6 sender6;
	struct timeval rtt;
	struct timeval sent_time;
};

u_int16_t compute_icmp_checksum(const void *buff, int length);
void trace(char *destination_string, char *database, uint16_t probes_per_turn, int max_ttl, int probe_type);
void trace6(char *destination_string, char *database, uint16_t probes_per_turn, int max_ttl, int probe_type);
void construct_sockaddr(struct sockaddr_in *address, sa_family_t family, char *address_string);
void construct_sockaddr6(struct sockaddr_in6 *address, sa_family_t family, char *address_string);
void construct_icmphdr(struct icmphdr *header, uint8_t type, uint8_t code, uint16_t id, uint16_t sequence);
void reset_replies(int n, struct reply array[n]);
void send_probes(int sockfd, struct sockaddr_in dest, int ttl, int probes, uint16_t id, uint16_t *seq_ptr, struct reply replies[]);
void send_probes6(int sockfd, struct sockaddr_in6 dest, int ttl, int probes, uint16_t id, uint16_t *seq_ptr, struct reply replies[]);
void send_udp_probes(int sockfd, struct sockaddr_in dest, int ttl, int probes, uint16_t base_port, struct reply replies[]);
void send_udp_probes6(int sockfd, struct sockaddr_in6 dest, int ttl, int probes, uint16_t base_port, struct reply replies[]);
void set_time(struct timeval *tv, time_t sec, suseconds_t usec);
int check_for_answers(int sockfd, int ttl, uint16_t id, uint16_t probes_per_turn, struct reply replies[probes_per_turn], int probe_type);
void analyze_packet(u_int8_t* buffer, int ip_version, uint8_t* returned_type_p, uint16_t* returned_id_p, uint16_t* returned_seq_p);
void receive_packets(int sockfd, int ttl, uint16_t id, uint16_t probes_per_turn, struct reply replies[probes_per_turn], int *packets_left_ptr, struct timeval tv, int *destination_reached, int probe_type);
void print_traceroute(uint16_t probes_per_turn, struct reply replies[probes_per_turn], uint16_t ttl, IP2Location *obj, int ip_version);