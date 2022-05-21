#include <cassert>
#include <cstring>
#include <iostream>

#include "Packet.h"
#include "VpnPacket.h"

// #define HOSTGATOR


int open_raw_socket_for_listening() {
	static constexpr auto AF_PACKET = 17;
	static constexpr auto PF_PACKET = AF_PACKET;
	static constexpr auto SOCK_RAW_ = 3;
	static constexpr auto ETH_P_ALL = 0x0003;
	int sd_incoming = socket(PF_PACKET, SOCK_RAW_, htons(ETH_P_ALL));
	return sd_incoming;
}


int main() {
	int sd_incoming = open_raw_socket_for_listening();
	if (sd_incoming == -1) {
		std::cerr << "Error while opening raw socket: socket() error " << errno << ": " << strerror(errno) << std::endl;
		exit(1);
	}
	std::cout << "Listening on the wire..." << std::endl;
	while (true) {
		// Raw packet capture
		uint8_t buffer[Ip::IP_MAXPACKET];
		socklen_t size;
		struct sockaddr_in from;
		socklen_t fromlen = sizeof(from);
		size = recvfrom(sd_incoming, reinterpret_cast<char*>(buffer), sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&from), &fromlen);
		// std::cout << std::endl << "Receiving " << size << " bytes" << std::endl;


		// There are two possible cases:
		//    1. In HostGator VPS, we receive IP packets (layer 3).
		//    2. In Linux box, we receive DataLink packets (layer 2).
		// So it is better to use IP packets since it works everywhere.
		Ip* ip;


#ifdef HOSTGATOR
		// Layer 3: IP packet
		ip = reinterpret_cast<Ip*>(buffer);
#else
		{
			// Layer 2: Ethernet packet
			Eth* eth = reinterpret_cast<Eth*>(buffer);
			eth->print_header();
			eth->print_header_raw();
			if (ntohs(eth->h_proto) != Eth::ETH_P_IP) continue;

			// Layer 3: IP packet
			ip = reinterpret_cast<Ip*>(eth->payload());
			size -= eth->header_len();
		}
#endif // HOSTGATOR

		// Layer 3
		ip->print_header();
		ip->print_header_raw();
		{
			// Verify that our IP checksum algorithm is correct
			uint16_t original_checksum = ip->check;
			ip->check = 0;
			ip->check = ip->checksum();
			if (ip->check != original_checksum) {
				std::cerr << "IP checksum does not match " << original_checksum << " != " << ip->check << std::endl;
			}
		}


		// Layer 4
		switch (ip->protocol) {
		case Ip::IPPROTO_TCP:
		{
			Tcp* tcp = reinterpret_cast<Tcp*>(ip->payload());
			// Skip processing SSH packets
			if (ntohs(tcp->source) == 22 || ntohs(tcp->dest) == 22) {
				continue;
			}
			tcp->print_header();
			tcp->print_header_raw();
			std::cout << "Payload:" << std::endl;
			Util::print_raw(tcp->payload(), ip->total_len() - ip->header_len() - tcp->header_len());
			{
				// Verify that our TCP checksum algorithm is correct
				// How to disable checksum offloading: ethtool -K eth0 rx off tx off   (https://stackoverflow.com/questions/15538786/how-is-tcps-checksum-calculated-when-we-use-tcpdump-to-capture-packets-which-we)
				int len = ip->total_len() - ip->header_len();
				uint16_t original_checksum = tcp->check;
				tcp->check = 0;
				tcp->check = tcp->checksum(len, ip->saddr, ip->daddr);
				if (tcp->check != original_checksum) {
					std::cerr << "TCP checksum does not match " << original_checksum << " != " << tcp->check << std::endl;
				}
			}
			std::cout << std::endl;
			break;
		}

		case Ip::IPPROTO_UDP:
		{
			Udp* udp = reinterpret_cast<Udp*>(ip->payload());
			udp->print_header();
			udp->print_header_raw();
			std::cout << "Payload:" << std::endl;
			udp->print_payload_raw();
			// std::cout << "Payload:" << std::endl;
			// Util::print_raw(udp->payload(), ip->total_len() - ip->header_len() - udp->header_len());
			{
				// Verify that our UDP checksum algorithm is correct
				int len = ip->total_len() - ip->header_len();
				uint16_t original_checksum = udp->check;
				udp->check = 0;
				udp->check = udp->checksum(len, ip->saddr, ip->daddr);
				if (udp->check != original_checksum) {
					std::cerr << "UDP checksum does not match " << original_checksum << " != " << udp->check << std::endl;
				}
			}
			std::cout << std::endl;
			break;
		}

		case Ip::IPPROTO_ICMP:
		{
			Icmp* icmp = reinterpret_cast<Icmp*>(ip->payload());
			icmp->print_header();
			{
				// Verify that our ICMP checksum algorithm is correct
				int len = ip->total_len() - ip->header_len();
				uint16_t original_checksum = icmp->check;
				icmp->check = 0;
				icmp->check = icmp->checksum(len);
				if (icmp->check != original_checksum) {
					std::cerr << "ICMP checksum does not match " << original_checksum << " != " << icmp->check << std::endl;
				}
			}
			std::cout << std::endl;
			break;
		}

		default:
			// Ignore non TCP, UDP or ICMP packet
			continue;
		}
	}
	return 0;
}
