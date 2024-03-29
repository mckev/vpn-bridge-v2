#include <cassert>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <sstream>
#include "Packet.h"


// --- UTILITY ---

uint16_t Util::calculate_checksum(const void* buffer, int len, int proto, uint32_t src_addr, uint32_t dest_addr) {
	// Ref:
	// IP: http://www.pdbuchan.com/rawsock/tcp4.c
	// TCP: http://minirighi.sourceforge.net/html/tcp_8c-source.html
	// UDP: http://minirighi.sourceforge.net/html/udp_8c-source.html

	const uint16_t* w = static_cast<const uint16_t*>(buffer);
	int nleft = len;
	uint32_t sum = 0;
	while (nleft > 1) {
		sum += *w++;
		if (sum & 0x80000000) {
			sum = (sum & 0xFFFF) + (sum >> 16);
		}
		nleft -= 2;
	}
	if (nleft == 1) {
		sum += *(reinterpret_cast<const uint8_t*>(w));
	}

	// Add the pseudo headers
	if (proto != 0) {
		const uint16_t* ip_src = reinterpret_cast<const uint16_t*>(&src_addr);
		const uint16_t* ip_dst = reinterpret_cast<const uint16_t*>(&dest_addr);
		sum += *(ip_src++);
		sum += *ip_src;
		sum += *(ip_dst++);
		sum += *ip_dst;
		sum += htons(proto);
		sum += htons(len);
	}

	// Add the carries
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	// Return the invert of sum
	return static_cast<uint16_t>(~sum);
}

void Util::print_raw(const uint8_t* buffer, int len) {
	int x = 0;
	std::stringstream cleartext;
	std::cout << std::hex;
	for (int i = 0; i < len; i++) {
		std::cout << std::setfill('0') << std::setw(2) << (int)buffer[i] << " ";
		cleartext << (std::isprint(buffer[i]) ? (char)buffer[i] : (char)'.');
		x++;
		if (x % 16 == 0) {
			std::cout << "        " << cleartext.str() << std::endl;
			cleartext.str("");
			x = 0;
		}
	}
	std::cout << "        " << cleartext.str() << std::endl;
	std::cout << std::dec;
}




// --- LAYER 2: ETHERNET ---

int Eth::header_len() const {
	return sizeof(Eth);
}

uint8_t* Eth::payload() {
	return reinterpret_cast<uint8_t*>(this) + header_len();
}

void Eth::print_header() const {
	std::cout << "Ethernet Header" << std::endl
		<< "   |-Destination Address  : " << Eth::mac_addr_to_str(h_dest) << std::endl
		<< "   |-Source Address       : " << Eth::mac_addr_to_str(h_source) << std::endl
		<< "   |-Protocol             : " << ntohs(h_proto) << std::endl;
}

void Eth::print_header_raw() const {
	Util::print_raw(reinterpret_cast<const uint8_t*>(this), header_len());
}

std::string Eth::mac_addr_to_str(const uint8_t* mac_addr)
{
	std::stringstream buffer;
	buffer << std::hex << std::setfill('0') << std::setw(2) << (int)mac_addr[0] << ":" << std::setfill('0') << std::setw(2) << (int)mac_addr[1] << ":" << std::setfill('0') << std::setw(2) << (int)mac_addr[2] << ":" << std::setfill('0') << std::setw(2) << (int)mac_addr[3] << ":" << std::setfill('0') << std::setw(2) << (int)mac_addr[4] << ":" << std::setfill('0') << std::setw(2) << (int)mac_addr[5] << std::dec;
	return buffer.str();
}




// --- LAYER 3: IP ---

int Ip::header_len() const {
	// ip header length is usually 20 bytes
	return ihl * 4;
}

int Ip::total_len() const {
	// size of packet
	return ntohs(tot_len);
}

uint8_t* Ip::payload() {
	return reinterpret_cast<uint8_t*>(this) + header_len();
}

void Ip::print_header() const {
	std::cout << "IP Header" << std::endl
		<< "   |-IP Version           : " << (int)version << std::endl
		<< "   |-IP Header Length     : " << (int)ihl << " dwords or " << ihl * 4 << " bytes" << std::endl;
	if (ihl != 5) {
		std::cout << "                            (IHL > 5: IP Options exists)" << std::endl;
	}
	std::cout
		<< "   |-Type Of Service      : " << (int)tos << std::endl
		<< "   |-IP Total Length      : " << ntohs(tot_len) << " bytes (Size of Packet)" << std::endl
		<< "   |-Identification       : " << ntohs(id) << std::endl
		<< "   |-TTL                  : " << (int)ttl << std::endl
		<< "   |-Protocol             : " << (int)protocol << std::endl
		<< "   |-Checksum             : " << check << std::endl
		<< "   |-Source IP            : " << Ip::ip_addr_to_str(saddr) << std::endl
		<< "   |-Destination IP       : " << Ip::ip_addr_to_str(daddr) << std::endl;
}

void Ip::print_header_raw() const {
	Util::print_raw(reinterpret_cast<const uint8_t*>(this), header_len());
}

uint16_t Ip::checksum() const {
	// Set ip->check to 0 before calling this function
	assert(this->check == 0);

	return Util::calculate_checksum(this, header_len(), 0, 0, 0);
}

std::string Ip::ip_addr_to_str(uint32_t ip_addr) {
	const uint8_t* p = reinterpret_cast<uint8_t*>(&ip_addr);
	std::stringstream buffer;
	buffer << (int)p[0] << "." << (int)p[1] << "." << (int)p[2] << "." << (int)p[3];
	return buffer.str();
}




// --- LAYER 4: TCP ---

int Tcp::header_len() const {
	return doff * 4;
}

uint8_t* Tcp::payload() {
	return reinterpret_cast<uint8_t*>(this) + header_len();
}

void Tcp::print_header() const {
	std::cout << "TCP Header" << std::endl
		<< "   |-Source Port          : " << ntohs(source) << std::endl
		<< "   |-Destination Port     : " << ntohs(dest) << std::endl
		<< "   |-Sequence Number      : " << ntohl(seq) << std::endl
		<< "   |-Acknowledge Number   : " << ntohl(ack_seq) << std::endl
		<< "   |-Header Length        : " << doff << " dwords or " << doff * 4 << " bytes" << std::endl;
	if (doff != 5) {
		std::cout << "                            (Data offset > 5: TCP Options exists)" << std::endl;
	}
	std::cout
		<< "   |-Reserved             : " << res1 << std::endl
		<< "   |-CWR Flag             : " << cwr << std::endl
		<< "   |-ECN Flag             : " << ece << std::endl
		<< "   |-Urgent Flag          : " << urg << std::endl
		<< "   |-Acknowledgement Flag : " << ack << std::endl
		<< "   |-Push Flag            : " << psh << std::endl
		<< "   |-Reset Flag           : " << rst << std::endl
		<< "   |-Synchronise Flag     : " << syn << std::endl
		<< "   |-Finish Flag          : " << fin << std::endl
		<< "   |-Window               : " << ntohs(window) << std::endl
		<< "   |-Checksum             : " << check << std::endl
		<< "   |-Urgent Pointer       : " << urg_ptr << std::endl;
}

void Tcp::print_header_raw() const {
	Util::print_raw(reinterpret_cast<const uint8_t*>(this), header_len());
}

uint16_t Tcp::checksum(int len, uint32_t src_addr, uint32_t dest_addr) const {
	// Set tcp->check to 0 before calling this function
	assert(this->check == 0);

	return Util::calculate_checksum(this, len, Ip::IPPROTO_TCP, src_addr, dest_addr);
}




// --- LAYER 4: UDP ---

int Udp::header_len() const {
	return sizeof(Udp);
}

int Udp::total_len() const {
	return ntohs(len);
}

uint8_t* Udp::payload() {
	return reinterpret_cast<uint8_t*>(this) + header_len();
}

void Udp::print_header() const {
	std::cout << "UDP Header" << std::endl
		<< "   |-Source Port          : " << ntohs(source) << std::endl
		<< "   |-Destination Port     : " << ntohs(dest) << std::endl
		<< "   |-UDP Length           : " << ntohs(len) << std::endl
		<< "   |-UDP Checksum         : " << check << std::endl;
}

void Udp::print_header_raw() const {
	Util::print_raw(reinterpret_cast<const uint8_t*>(this), header_len());
}

void Udp::print_payload_raw() const {
	Util::print_raw(reinterpret_cast<const uint8_t*>(this) + header_len(), total_len() - header_len());
}

uint16_t Udp::checksum(int len, uint32_t src_addr, uint32_t dest_addr) const {
	// Set udp->check to 0 before calling this function
	assert(this->check == 0);

	return Util::calculate_checksum(this, len, Ip::IPPROTO_UDP, src_addr, dest_addr);
}




// --- LAYER 4: ICMP ---

void Icmp::print_header() const {
	std::cout << "ICMP Header" << std::endl
		<< "   |-Type                 : " << (int)type << std::endl;
	if (type == Icmp::ICMP_TIME_EXCEEDED) {
		std::cout << "                            (TTL Expired)" << std::endl;
	}
	else if (type == Icmp::ICMP_ECHOREPLY) {
		std::cout << "                            (ICMP Echo Reply)" << std::endl;
	}
	std::cout
		<< "   |-Code                 : " << (int)code << std::endl
		<< "   |-Checksum             : " << ntohs(check) << std::endl;
}

uint16_t Icmp::checksum(int len) const {
	// Set icmp->check to 0 before calling this function
	assert(this->check == 0);

	return Util::calculate_checksum(this, len, 0, 0, 0);
}
