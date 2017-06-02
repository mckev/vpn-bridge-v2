#ifndef PACKET_H_
#define PACKET_H_


#include <cstdint>


#pragma pack(1)                                             // disable alignment of struct members
#define __LITTLE_ENDIAN_BITFIELD                            // intel is using little-endian format


class Eth {
    public:
    // from: linux/if_ether.h
    static const int ETH_ALEN       = 6;                    // octets in one ethernet address
    static const int ETH_P_IP       = 0x0800;               // ip packet

    uint8_t         h_dest[ETH_ALEN];                       // destination ethernet address
    uint8_t         h_source[ETH_ALEN];                     // source ethernet address
    uint16_t        h_proto;                                // packet type id

    void print_eth() const;
};


class Ip {
    public:
    #if defined (__LITTLE_ENDIAN_BITFIELD)
    uint8_t         ihl:4, version:4;
    #elif defined (__BIG_ENDIAN_BITFIELD)
    uint8_t         version:4, ihl:4;
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

    static const int IP_MAXPACKET   = 0xFFFF;
    // from: linux/in.h
    static const int IPPROTO_ICMP   = 1;
    static const int IPPROTO_TCP    = 6;
    static const int IPPROTO_UDP    = 17;

    void print_ip() const;
};


// Socket definitions
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
typedef int socklen_t;
extern "C" socklen_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);


#endif /* PACKET_H_ */
