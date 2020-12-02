#include "trace.h"
#include "error.h"

u_int16_t compute_icmp_checksum(const void *buff, int length)
{
	u_int32_t sum;
	const u_int16_t *ptr = buff;
	assert(length % 2 == 0);
	
	for (sum = 0; length > 0; length -= 2) {
		sum += *ptr++;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	
	return (u_int16_t)(~(sum + (sum >> 16)));
}

void construct_sockaddr(struct sockaddr_in *address, sa_family_t family, char *address_string)
{
	bzero(address, sizeof(*address));
	address->sin_family = family;
	Inet_pton(address->sin_family, address_string, &(address->sin_addr));
}

void construct_icmphdr(struct icmphdr *header, uint8_t type, uint8_t code, uint16_t id, uint16_t sequence)
{
	header->type = type;
	header->code = code;
	header->un.echo.id = id;
	header->un.echo.sequence = sequence;
	header->checksum = 0;
	header->checksum = compute_icmp_checksum((u_int16_t *)header, sizeof(*header));
}

void reset_replies(int n, struct reply array[n])
{
	for (int i = 0; i < n; i++) {
		array[i].replied = 0;
	}
}

void send_probes(int sockfd, struct sockaddr_in dest, int ttl, int probes, uint16_t id, uint16_t *seq_ptr)
{
	struct icmphdr header;
	
	for (int i = 0; i < probes; i++, (*seq_ptr)++) {
		construct_icmphdr(&header, ICMP_ECHO, 0, id, *seq_ptr);
		Setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int));
		Sendto(sockfd, &header, sizeof(header), 0, (struct sockaddr *)&dest, sizeof(dest));
	}
}

void set_time(struct timeval *tv, time_t sec, suseconds_t usec)
{
	tv->tv_usec = usec;
	tv->tv_sec = sec;
}

int check_for_answers(int sockfd, int ttl, uint16_t id, uint16_t probes_per_turn, struct reply replies[probes_per_turn])
{
	int packets_left = probes_per_turn;
	int ready;
	struct timeval tv;
	set_time(&tv, 0, 1000000);
	fd_set descriptors;
	int destination_reached = 0;
	
	do {
		FD_ZERO(&descriptors);
		FD_SET(sockfd, &descriptors);
		ready = Select(sockfd + 1, &descriptors, NULL, NULL, &tv);
		
		if (ready > 0) {
			receive_packets(sockfd, ttl, id, probes_per_turn, replies, &packets_left, tv, &destination_reached);
		}

	} while (ready > 0 && packets_left > 0);

	return destination_reached;
}

void analize_packet(u_int8_t *buffer, uint8_t *returned_type_p, uint16_t *returned_id_p, uint16_t *returned_seq_p)
{
	struct ip *ip_header;
	ssize_t ip_header_len;
	struct icmphdr *returned_icmp_p;
	uint8_t returned_type;
	uint16_t returned_id;
	uint16_t returned_seq;

	ip_header = (struct ip *)buffer;
	ip_header_len = 4 * ((*(uint8_t *)ip_header) & 0xf);
	returned_icmp_p = (void *)ip_header + ip_header_len;
	returned_type = returned_icmp_p->type;

	if (returned_type == ICMP_TIME_EXCEEDED) {
		struct icmphdr *old_icmp_p = (void *)returned_icmp_p + ip_header_len + 8;
		returned_id = old_icmp_p->un.echo.id;
		returned_seq = old_icmp_p->un.echo.sequence;
	} else {
		returned_id = returned_icmp_p->un.echo.id;
		returned_seq = returned_icmp_p->un.echo.sequence;
	}

	*returned_type_p = returned_type;
	*returned_seq_p = returned_seq;
	*returned_id_p = returned_id;
}

void receive_packets(int sockfd, int ttl, uint16_t id, uint16_t probes_per_turn, struct reply replies[probes_per_turn], int *packets_left_ptr, struct timeval tv, int *destination_reached)
{
	ssize_t packet_len = 0;
	struct sockaddr_in sender;
	socklen_t sender_len = sizeof(sender);
	u_int8_t buffer[IP_MAXPACKET];

	uint8_t returned_type;
	uint16_t returned_id;
	uint16_t returned_seq;

	while (1) {
		packet_len = Recvfrom(sockfd, buffer, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr *)&sender, &sender_len);
		
		if (packet_len == -1) {
			break;
		}

		analize_packet(buffer, &returned_type, &returned_id, &returned_seq);

		if (returned_id == id) {
			if (returned_seq / probes_per_turn == ttl || returned_type == ICMP_ECHOREPLY) {
				if (returned_type == ICMP_ECHOREPLY) {
					*destination_reached = 1;
				}

				replies[probes_per_turn - *packets_left_ptr].replied = 1;
				replies[probes_per_turn - *packets_left_ptr].sender = sender;
				replies[probes_per_turn - *packets_left_ptr].tv.tv_usec = 1000000 - tv.tv_usec;
				(*packets_left_ptr)--;
			} else {
				continue;
			}

			if (*packets_left_ptr == 0) {
				break;
			}
		} else {
			break;
		}
	}
}

void print_traceroute(uint16_t probes_per_turn, struct reply replies[probes_per_turn], uint16_t ttl, IP2Location *obj)
{
	int packets = 0;
	struct timeval time_sum;
	set_time(&time_sum, 0, 0);
	char ip_str[20];
	IP2LocationRecord *record = NULL;

	printf("%d", ttl);
	printf(".");

	if (ttl < 10) {
		printf("  ");
	} else {
		printf(" ");
	}

	for (int i = 0; i < probes_per_turn; i++) {
		if (replies[i].replied) {
			packets++;
			time_sum.tv_usec += replies[i].tv.tv_usec;
			int is_address_new = 1;
			
			for (int j = 0; j < i; j++) {
				if (replies[j].sender.sin_addr.s_addr == replies[i].sender.sin_addr.s_addr) {
					is_address_new = 0;
				}
			}

			if (is_address_new) {
				Inet_ntop(AF_INET, &(replies[i].sender.sin_addr), ip_str, sizeof(ip_str));

				if (obj != NULL) {
					record = IP2Location_get_all(obj, ip_str);
				}

				printf("%s ", ip_str);
			}
		}
	}

	if (packets == 0) {
		printf("*\n");
	} else if (packets < probes_per_turn) {
		printf("???");
	} else {
		printf("%ld", (time_sum.tv_usec / packets) / 1000);
		printf("ms");
	}

	if (obj == NULL) {
		if (packets != 0) {
			printf(" [Missing IP2Location Database]\n");
		}
	} else if (record != NULL) {
		switch (obj->database_type) {
			case 1:
				printf(" [\"%s\",\"%s\"]\n", record->country_short, record->country_long);
				break;

			case 2:
				printf(" [\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->isp);
				break;

			case 3:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city);
				break;

			case 4:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->isp);
				break;

			case 5:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude);
				break;

			case 6:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->isp);
				break;

			case 7:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->isp, record->domain);
				break;

			case 8:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->isp, record->domain);
				break;

			case 9:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode);
				break;

			case 10:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->isp, record->domain);
				break;

			case 11:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->timezone);
				break;

			case 12:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->isp, record->domain, record->timezone);
				break;

			case 14:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->isp, record->domain, record->timezone, record->netspeed);
				break;

			case 15:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->timezone, record->iddcode, record->areacode);
				break;

			case 16:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->isp, record->domain, record->timezone, record->netspeed, record->iddcode, record->areacode);
				break;

			case 17:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->timezone, record->netspeed, record->weatherstationcode, record->weatherstationname);
				break;

			case 18:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->isp, record->domain, record->timezone, record->netspeed, record->iddcode, record->areacode, record->weatherstationcode, record->weatherstationname);
				break;

			case 19:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->isp, record->domain, record->mcc, record->mnc, record->mobilebrand);
				break;

			case 20:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->isp, record->domain, record->timezone, record->netspeed, record->iddcode, record->areacode, record->weatherstationcode, record->weatherstationname, record->mcc, record->mnc, record->mobilebrand);
				break;

			case 21:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%.1f\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->timezone, record->iddcode, record->areacode, record->elevation);
				break;

			case 22:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%.1f\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->isp, record->domain, record->timezone, record->netspeed, record->iddcode, record->areacode, record->weatherstationcode, record->weatherstationname, record->mcc, record->mnc, record->mobilebrand, record->elevation);
				break;

			case 23:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->isp, record->domain, record->mcc, record->mnc, record->mobilebrand, record->usagetype);
				break;

			case 24:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%.1f\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->isp, record->domain, record->timezone, record->netspeed, record->iddcode, record->areacode, record->weatherstationcode, record->weatherstationname, record->mcc, record->mnc, record->mobilebrand, record->elevation, record->usagetype);
				break;

		}

		IP2Location_free_record(record);
	}
}

void trace(char *destination_string, char *database, uint16_t probes_per_turn, int max_ttl)
{
	struct sockaddr_in destination;
	construct_sockaddr(&destination, AF_INET, destination_string);
	IP2Location *obj = NULL;

	if (database != NULL) {
		obj = IP2Location_open((char *)database);
	}

	pid_t mypid = getpid();

	struct icmphdr header;
	construct_icmphdr(&header, ICMP_ECHO, 0, mypid, 0);

	int sockfd = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	struct reply replies[probes_per_turn];
	uint16_t seq = probes_per_turn;
	int destination_reached = 0;

	for (int ttl = 1; ttl <= max_ttl; ttl++) {
		reset_replies(probes_per_turn, replies);
		send_probes(sockfd, destination, ttl, probes_per_turn, mypid, &seq);
		destination_reached = check_for_answers(sockfd, ttl, mypid, probes_per_turn, replies);
		print_traceroute(probes_per_turn, replies, ttl, obj);
		
		if (destination_reached) {
			break;
		}
	}

	Close(sockfd);

	IP2Location_close(obj);
}