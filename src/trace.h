#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <assert.h>
#include <sys/select.h>
#include <sys/time.h>
#include <IP2Location.h>

struct reply
{
	struct timeval tv;
	struct sockaddr_in sender;
	int replied;
};

u_int16_t compute_icmp_checksum(const void *buff, int length);
void trace(char *destination_string, char *database, uint16_t probes_per_turn, int max_ttl);
void construct_sockaddr(struct sockaddr_in *address, sa_family_t family, char *address_string);
void construct_icmphdr(struct icmphdr *header, uint8_t type, uint8_t code, uint16_t id, uint16_t sequence);
void reset_replies(int n, struct reply array[n]);
void send_probes(int sockfd, struct sockaddr_in dest, int ttl, int probes, uint16_t id, uint16_t *seq_ptr);
void set_time(struct timeval *tv, time_t sec, suseconds_t usec);
int check_for_answers(int sockfd, int ttl, uint16_t id, uint16_t probes_per_turn, struct reply replies[probes_per_turn]);
void analize_packet(u_int8_t *buffer, uint8_t *returned_type_p, uint16_t *returned_id_p, uint16_t *returned_seq_p);
void receive_packets(int sockfd, int ttl, uint16_t id, uint16_t probes_per_turn, struct reply replies[probes_per_turn], int *packets_left_ptr, struct timeval tv, int *destination_reached);
void print_traceroute(uint16_t probes_per_turn, struct reply replies[probes_per_turn], uint16_t ttl, IP2Location *obj);