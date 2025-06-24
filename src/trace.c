#include "trace.h"

static inline uint16_t encode_probe_port(int base_port, int ttl, int probe_index, int probes_per_turn) {
	return base_port + (ttl * probes_per_turn) + probe_index;
}

static inline int decode_ttl_from_port(int base_port, uint16_t port, int probes_per_turn) {
	return (port - base_port) / probes_per_turn;
}

static inline int decode_probe_index_from_port(int base_port, uint16_t port, int probes_per_turn) {
	return (port - base_port) % probes_per_turn;
}

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

	if (inet_pton(address->sin_family, address_string, &(address->sin_addr)) != 1) {
		fprintf(stderr, "Error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
}

void construct_sockaddr6(struct sockaddr_in6 *address, sa_family_t family, char *address_string)
{
	bzero(address, sizeof(*address));
	address->sin6_family = family;
	
	if (inet_pton(address->sin6_family, address_string, &(address->sin6_addr)) != 1) {
		fprintf(stderr, "Error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
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

void send_probes(int sockfd, struct sockaddr_in dest, int ttl, int probes, uint16_t id, uint16_t *seq_ptr, struct reply replies[])
{
	int result;
	struct icmphdr header;
	
	for (int i = 0; i < probes; i++, (*seq_ptr)++) {
		gettimeofday(&replies[i].sent_time, NULL);
		construct_icmphdr(&header, ICMP_ECHO, 0, id, *seq_ptr);

		if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) == -1) {
			fprintf(stderr, "Set Socket Options Error: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		result = sendto(sockfd, &header, sizeof(header), 0, (struct sockaddr *)&dest, sizeof(dest));

		if (result == 0 || result == -1) {
			fprintf(stderr, "Send To Error: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

void send_probes6(int sockfd, struct sockaddr_in6 dest, int ttl, int probes, uint16_t id, uint16_t *seq_ptr, struct reply replies[])
{
	int result;
	struct icmp6_hdr header;

	for (int i = 0; i < probes; i++, (*seq_ptr)++) {
		gettimeofday(&replies[i].sent_time, NULL);

		// Fill ICMPv6 header
		header.icmp6_type = ICMP6_ECHO_REQUEST;
		header.icmp6_code = 0;
		header.icmp6_id = htons(id);
		header.icmp6_seq = htons(*seq_ptr);

		if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) == -1) {
			perror("setsockopt IPV6_UNICAST_HOPS");
			exit(EXIT_FAILURE);
		}

		result = sendto(sockfd, &header, sizeof(header), 0, (struct sockaddr*)&dest, sizeof(dest));
		if (result == -1) {
			perror("sendto ICMPv6");
			exit(EXIT_FAILURE);
		}
	}
}

void send_udp_probes(int sockfd, struct sockaddr_in dest, int ttl, int probes, uint16_t base_port, struct reply replies[])
{
	for (int i = 0; i < probes; i++) {
		gettimeofday(&replies[i].sent_time, NULL);
		if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) == -1) {
			fprintf(stderr, "Set TTL Error: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}

		struct sockaddr_in dest_copy = dest;
		dest_copy.sin_port = htons(encode_probe_port(base_port, ttl, i, probes));

		if (sendto(sockfd, "", 1, 0, (struct sockaddr*)&dest_copy, sizeof(dest_copy)) < 0) {
			fprintf(stderr, "UDP Send Error: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
}

void send_udp_probes6(int sockfd, struct sockaddr_in6 dest, int ttl, int probes, uint16_t base_port, struct reply replies[])
{
	// Set the TTL (hop limit) for this set of probes
	if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0) {
		perror("setsockopt(IPV6_UNICAST_HOPS)");
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < probes; i++) {
		int dest_port = base_port + ttl * probes + i;

		// Set the port for this probe
		dest.sin6_port = htons(encode_probe_port(base_port, ttl, i, probes));

		// Record the send time for this probe
		gettimeofday(&replies[i].sent_time, NULL);

		// Send an empty UDP datagram
		ssize_t sent = sendto(sockfd, NULL, 0, 0,
			(struct sockaddr*)&dest,
			sizeof(dest));

		if (sent < 0) {
			fprintf(stderr, "sendto failed on probe %d (TTL=%d, port=%d): %s\n",
				i, ttl, dest_port, strerror(errno));
		}
		else {
			// Optional: debug logging
			// printf("[SEND6][TTL=%d][i=%d] port=%d\n", ttl, i, dest_port);
		}
	}
}

void set_time(struct timeval *tv, time_t sec, suseconds_t usec)
{
	tv->tv_usec = usec;
	tv->tv_sec = sec;
}

int check_for_answers(int sockfd, int ttl, uint16_t id, uint16_t probes_per_turn,
	struct reply replies[probes_per_turn], int probe_type)
{
	int packets_left = probes_per_turn;
	int ready;
	struct timeval tv;
	set_time(&tv, 0, 1000000); // 1 second
	fd_set descriptors;
	int destination_reached = 0;

	do {
		FD_ZERO(&descriptors);
		FD_SET(sockfd, &descriptors);
		ready = select(sockfd + 1, &descriptors, NULL, NULL, &tv);

		if (ready == -1) {
			perror("select");
			exit(EXIT_FAILURE);
		}

		if (ready > 0) {
			receive_packets(sockfd, ttl, id, probes_per_turn, replies, &packets_left, tv, &destination_reached, probe_type);
		}

	} while (ready > 0 && packets_left > 0);

	return destination_reached;
}

void analyze_packet(u_int8_t* buffer, int ip_version, uint8_t* returned_type_p, uint16_t* returned_id_p, uint16_t* returned_seq_p)
{
	if (ip_version == 4) {
		struct ip* ip_header = (struct ip*)buffer;
		int ip_header_len = ip_header->ip_hl * 4;
		struct icmphdr* icmp = (struct icmphdr*)(buffer + ip_header_len);
		*returned_type_p = icmp->type;

		if (icmp->type == ICMP_TIME_EXCEEDED || icmp->type == ICMP_DEST_UNREACH) {
			struct ip* inner_ip = (struct ip*)(buffer + ip_header_len + sizeof(struct icmphdr));
			int inner_ip_len = inner_ip->ip_hl * 4;
			struct udphdr* inner_udp = (struct udphdr*)((u_int8_t*)inner_ip + inner_ip_len);
			*returned_id_p = 0;
			*returned_seq_p = ntohs(inner_udp->dest);
		}
		else {
			*returned_id_p = icmp->un.echo.id;
			*returned_seq_p = icmp->un.echo.sequence;
		}
	}
	else if (ip_version == 6) {
		struct icmp6_hdr* icmp6 = (struct icmp6_hdr*)buffer;
		*returned_type_p = icmp6->icmp6_type;

		if (icmp6->icmp6_type == ICMP6_TIME_EXCEEDED || icmp6->icmp6_type == ICMP6_DST_UNREACH) {
			uint8_t* ptr = buffer + sizeof(struct icmp6_hdr);
			struct ip6_hdr* inner_ip6 = (struct ip6_hdr*)ptr;
			ptr += sizeof(struct ip6_hdr);

			uint8_t next = inner_ip6->ip6_nxt;

			// Loop through extension headers
			while (next == IPPROTO_HOPOPTS || next == IPPROTO_ROUTING ||
				next == IPPROTO_FRAGMENT || next == IPPROTO_DSTOPTS ||
				next == IPPROTO_AH || next == IPPROTO_MH) {
				// Extension headers have same format: next header + hdr ext len
				struct {
					uint8_t next_header;
					uint8_t hdr_ext_len;
				} *ext = (void*)ptr;

				next = ext->next_header;
				ptr += (ext->hdr_ext_len + 1) * 8; // In 8-byte units, excluding first 8 bytes
			}

			if (next == IPPROTO_UDP) {
				struct udphdr* inner_udp = (struct udphdr*)ptr;
				*returned_id_p = 0;
				*returned_seq_p = ntohs(inner_udp->dest);
			}
			else if (next == IPPROTO_ICMPV6) {
				struct icmp6_hdr* inner_icmp6 = (struct icmp6_hdr*)ptr;
				*returned_id_p = ntohs(inner_icmp6->icmp6_id);
				*returned_seq_p = ntohs(inner_icmp6->icmp6_seq);
			}
			else {
				*returned_id_p = 0;
				*returned_seq_p = 0;
			}
		}
		else {
			*returned_id_p = ntohs(icmp6->icmp6_id);
			*returned_seq_p = ntohs(icmp6->icmp6_seq);
		}
	}
}

void receive_packets(int sockfd, int ttl, uint16_t id, uint16_t probes_per_turn,
	struct reply replies[probes_per_turn], int* packets_left_ptr, struct timeval tv,
	int* destination_reached, int probe_type)
{
	ssize_t packet_len;
	uint8_t buffer[IP_MAXPACKET];
	uint8_t returned_type;
	uint16_t returned_id, returned_seq;
	struct sockaddr_storage sender;
	socklen_t sender_len = sizeof(sender);

	while ((packet_len = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT,
		(struct sockaddr*)&sender, &sender_len)) > 0) {

		struct timeval now;
		gettimeofday(&now, NULL);

		int ip_version = sender.ss_family == AF_INET6 ? 6 : 4;

		analyze_packet(buffer, ip_version, &returned_type, &returned_id, &returned_seq);

		if (probe_type == 0) { // ICMP
			int index = returned_seq % probes_per_turn;
			if (index >= probes_per_turn) continue;

			// Always store sender if Time Exceeded
			if (returned_type == ICMP6_TIME_EXCEEDED || returned_type == ICMP_TIME_EXCEEDED) {
				replies[index].replied = 1;
				timersub(&now, &replies[index].sent_time, &replies[index].rtt);

				if (ip_version == 4) {
					memcpy(&replies[index].sender, (struct sockaddr_in*)&sender, sizeof(struct sockaddr_in));
				}
				else {
					memcpy(&replies[index].sender6, (struct sockaddr_in6*)&sender, sizeof(struct sockaddr_in6));
				}
				(*packets_left_ptr)--;
				continue; // Done for this packet
			}

			// For Echo Reply, require matching ID
			if (returned_id == id && (returned_type == ICMP_ECHOREPLY || returned_type == ICMP6_ECHO_REPLY)) {
				replies[index].replied = 1;
				timersub(&now, &replies[index].sent_time, &replies[index].rtt);

				if (ip_version == 4) {
					memcpy(&replies[index].sender, (struct sockaddr_in*)&sender, sizeof(struct sockaddr_in));
					if (returned_type == ICMP_ECHOREPLY) { // must use with the ip version check
						*destination_reached = 1;
					}
				}
				else {
					memcpy(&replies[index].sender6, (struct sockaddr_in6*)&sender, sizeof(struct sockaddr_in6));
					if (returned_type == ICMP6_ECHO_REPLY) {
						*destination_reached = 1;
					}
				}
				(*packets_left_ptr)--;
			}
		}
		else { // UDP
			int decoded_ttl = decode_ttl_from_port(33434, returned_seq, probes_per_turn);
			int index = decode_probe_index_from_port(33434, returned_seq, probes_per_turn);
			if (index >= probes_per_turn) continue;

			if (decoded_ttl == ttl) {
				replies[index].replied = 1;
				timersub(&now, &replies[index].sent_time, &replies[index].rtt);

				if (ip_version == 4) {
					memcpy(&replies[index].sender, (struct sockaddr_in*)&sender, sizeof(struct sockaddr_in));
					if (returned_type == ICMP_DEST_UNREACH) { // must use with the ip version check
							*destination_reached = 1;
					}
				}
				else {
					memcpy(&replies[index].sender6, (struct sockaddr_in6*)&sender, sizeof(struct sockaddr_in6));
					if (returned_type == ICMP6_DST_UNREACH) {
						*destination_reached = 1;
					}
				}

				(*packets_left_ptr)--;
			}
		}

		if (*packets_left_ptr == 0)
			break;
	}
}

void print_traceroute(uint16_t probes_per_turn, struct reply replies[probes_per_turn], uint16_t ttl, IP2Location *obj, int ip_version)
{
	int packets = 0;
	struct timeval time_sum;
	set_time(&time_sum, 0, 0);
	char ip_str[INET6_ADDRSTRLEN];
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
			time_sum.tv_usec += replies[i].rtt.tv_usec;
			int is_address_new = 1;
			
			for (int j = 0; j < i; j++) {
				if (ip_version == 4) {
					if (memcmp(&replies[j].sender.sin_addr, &replies[i].sender.sin_addr, sizeof(struct in_addr)) == 0)
					{
						is_address_new = 0;
					}
				} else {
					if (memcmp(&replies[j].sender6.sin6_addr, &replies[i].sender6.sin6_addr, sizeof(struct in6_addr)) == 0) 
					{
						is_address_new = 0;
					}
				}
			}

			if (is_address_new) {
				if (ip_version == 4) {
					if (inet_ntop(AF_INET, &(replies[i].sender.sin_addr), ip_str, sizeof(ip_str)) == NULL) {
						fprintf(stderr, "Error: %s\n", strerror(errno));
						exit(EXIT_FAILURE);
					}
				} else {
					if (inet_ntop(AF_INET6, &(replies[i].sender6.sin6_addr), ip_str, sizeof(ip_str)) == NULL) {
						fprintf(stderr, "Error: %s\n", strerror(errno));
						exit(EXIT_FAILURE);
					}
				}

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
		printf("%.4f", (float)(time_sum.tv_usec / packets) / 1000);
		printf(" ms");
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

			case 25:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%.1f\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->isp, record->domain, record->timezone, record->netspeed, record->iddcode, record->areacode, record->weatherstationcode, record->weatherstationname, record->mcc, record->mnc, record->mobilebrand, record->elevation, record->usagetype, record->address_type, record->category);
				break;

			case 26:
				printf(" [\"%s\",\"%s\",\"%s\",\"%s\",\"%.6f\",\"%.6f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%.1f\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]\n", record->country_short, record->country_long, record->region, record->city, record->latitude, record->longitude, record->zipcode, record->isp, record->domain, record->timezone, record->netspeed, record->iddcode, record->areacode, record->weatherstationcode, record->weatherstationname, record->mcc, record->mnc, record->mobilebrand, record->elevation, record->usagetype, record->address_type, record->category, record->district, record->asn, record->as);
				break;

		}

		IP2Location_free_record(record);
	}
}

void trace(char *destination_string, char *database, uint16_t probes_per_turn, int max_ttl, int probe_type)
{
	struct sockaddr_in destination;
	construct_sockaddr(&destination, AF_INET, destination_string);
	IP2Location *obj = NULL;

	if (database != NULL) {
		obj = IP2Location_open((char *)database);
	}

	pid_t mypid = getpid();

	if (probe_type == 0) {
		struct icmphdr header;
		construct_icmphdr(&header, ICMP_ECHO, 0, mypid, 0);
	}

	int sockfd;
	int sockfd2 = -1;
	if (probe_type == 0) {
		sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	}
	else {
		sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		sockfd2 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	}

	if (sockfd == -1) {
		fprintf(stderr, "Error in socket, error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct reply replies[probes_per_turn];
	uint16_t seq = probes_per_turn;
	int destination_reached = 0;

	for (int ttl = 1; ttl <= max_ttl; ttl++) {
		reset_replies(probes_per_turn, replies);
		if (probe_type == 0) {
			send_probes(sockfd, destination, ttl, probes_per_turn, mypid, &seq, replies);
			destination_reached = check_for_answers(sockfd, ttl, mypid, probes_per_turn, replies, probe_type);
		}
		else {
			send_udp_probes(sockfd, destination, ttl, probes_per_turn, 33434, replies);
			destination_reached = check_for_answers(sockfd2, ttl, mypid, probes_per_turn, replies, probe_type);
		}
		print_traceroute(probes_per_turn, replies, ttl, obj, 4);
		
		if (destination_reached) {
			break;
		}
	}

	if (close(sockfd) == -1) {
		exit(EXIT_FAILURE);
	}
	if (sockfd2 != -1) close(sockfd2);

	IP2Location_close(obj);
}

void trace6(char *destination_string, char *database, uint16_t probes_per_turn, int max_ttl, int probe_type)
{
	struct sockaddr_in6 destination;
	construct_sockaddr6(&destination, AF_INET6, destination_string);
	IP2Location *obj = NULL;

	if (database != NULL) {
		obj = IP2Location_open((char *)database);
	}

	pid_t mypid = getpid();

	if (probe_type == 0) {
		struct icmphdr header;
		construct_icmphdr(&header, ICMP_ECHO, 0, mypid, 0);
	}

	int sockfd;
	int sockfd2 = -1;
	if (probe_type == 0) {
		sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	}
	else {
		sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		sockfd2 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	}

	if (sockfd == -1) {
		fprintf(stderr, "Error in socket, error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	struct reply replies[probes_per_turn];
	uint16_t seq = probes_per_turn;
	int destination_reached = 0;

	for (int ttl = 1; ttl <= max_ttl; ttl++) {
		reset_replies(probes_per_turn, replies);
		if (probe_type == 0) {
			send_probes6(sockfd, destination, ttl, probes_per_turn, mypid, &seq, replies);
			destination_reached = check_for_answers(sockfd, ttl, mypid, probes_per_turn, replies, probe_type);
		}
		else {
			send_udp_probes6(sockfd, destination, ttl, probes_per_turn, 33434, replies);
			destination_reached = check_for_answers(sockfd2, ttl, mypid, probes_per_turn, replies, probe_type);
		}
		print_traceroute(probes_per_turn, replies, ttl, obj, 6);
		
		if (destination_reached) {
			break;
		}
	}

	if (close(sockfd) == -1) {
		exit(EXIT_FAILURE);
	}
	if (sockfd2 != -1) close(sockfd2);

	IP2Location_close(obj);
}