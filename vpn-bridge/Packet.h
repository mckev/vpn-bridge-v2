#ifndef PACKET_H_
#define PACKET_H_


#ifdef _WIN32
#include <winsock2.h>
#endif
#include <cstdint>


#pragma pack(1)                                             // disable alignment of struct members
#define __LITTLE_ENDIAN_BITFIELD							// intel is using little-endian format


// Utility

class Util {
public:
	static uint16_t calculate_checksum(const void* buffer, int len, int proto, uint32_t src_addr, uint32_t dest_addr);
};


// Layer 2

class Eth {
public:
	static constexpr auto ETH_ALEN = 6;						// octets in one ethernet address
	static constexpr auto ETH_P_IP = 0x0800;				// ip packet

	uint8_t         h_dest[ETH_ALEN];                       // destination ethernet address
	uint8_t         h_source[ETH_ALEN];                     // source ethernet address
	uint16_t        h_proto;                                // packet type id

	void print() const;
	void print_raw() const;
	static std::string mac_addr_to_str(const uint8_t* mac_addr);
};


// Layer 3

class Ip {
public:
	static constexpr auto IP_MAXPACKET = 0xFFFF;
	static constexpr auto IPPROTO_ICMP = 1;
	static constexpr auto IPPROTO_TCP = 6;
	static constexpr auto IPPROTO_UDP = 17;

#if defined (__LITTLE_ENDIAN_BITFIELD)
	uint8_t         ihl : 4, version : 4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t         version : 4, ihl : 4;
#else
#error "Unknown bitfield type"
#endif
	uint8_t         tos;
	uint16_t        tot_len;
	uint16_t        id;
	uint16_t        frag_off;
	uint8_t         ttl;
	uint8_t         protocol;
	uint16_t        check;
	uint32_t        saddr;
	uint32_t        daddr;

	void print() const;
	void print_raw() const;
	uint16_t checksum() const;
	static std::string ip_addr_to_str(uint32_t ip_addr);
};


// Layer 4

class Tcp {
public:
	uint16_t        source;
	uint16_t        dest;
	uint32_t        seq;
	uint32_t        ack_seq;
#if defined (__LITTLE_ENDIAN_BITFIELD)
	uint16_t        res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint16_t        doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
#error "Unknown bitfield type"
#endif
	uint16_t        window;
	uint16_t        check;
	uint16_t        urg_ptr;

	void print() const;
	uint16_t checksum(int len, uint32_t src_addr, uint32_t dest_addr) const;
};

class Udp {
public:
	uint16_t        source;
	uint16_t        dest;
	uint16_t        len;
	uint16_t        check;

	void print() const;
	uint16_t checksum(int len, uint32_t src_addr, uint32_t dest_addr) const;
};

class Icmp {
public:
	static constexpr auto ICMP_ECHOREPLY = 0;
	static constexpr auto ICMP_TIME_EXCEEDED = 11;

	uint8_t         type;
	uint8_t         code;
	uint16_t        check;
	union {
		struct {
			uint16_t    id;
			uint16_t    sequence;
		} echo;
		uint32_t    gateway;
		struct {
			uint16_t    __unused;
			uint16_t    mtu;
		} frag;
	} un;

	void print() const;
	uint16_t checksum(int len) const;
};


// Socket definitions
typedef int socklen_t;

#ifdef __linux__
extern "C" uint32_t htonl(uint32_t hostlong);
extern "C" uint16_t htons(uint16_t hostshort);
extern "C" uint32_t ntohl(uint32_t netlong);
extern "C" uint16_t ntohs(uint16_t netshort);
extern "C" int socket(int domain, int type, int protocol);
struct in_addr {
	uint32_t        s_addr;                                 // load with inet_aton()
};
struct sockaddr {
	uint16_t        sa_family;
	uint8_t         sa_data[14];
};
struct sockaddr_in {
	int16_t         sin_family;                             // e.g. AF_INET
	uint16_t        sin_port;                               // e.g. htons(3490)
	struct in_addr  sin_addr;
	uint8_t         sin_zero[8];
};
extern "C" socklen_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
#endif


#endif /* PACKET_H_ */
