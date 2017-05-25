#ifndef PACKET_H_
#define PACKET_H_


#include <cstdint>


class Eth {
    public:
    // from: linux/if_ether.h
    static const int ETH_ALEN = 6;                          // octets in one ethernet address
    static const int ETH_P_IP = 0x0800;                     // Internet Protocol packet
    uint8_t     h_dest[ETH_ALEN];                           // destination ethernet address
    uint8_t     h_source[ETH_ALEN];                         // source ethernet address
    uint16_t    h_proto;                                    // packet type id
};


class Ip: Eth {
    public:
    static const int IP_MAXPACKET = 0xFFFF;
};


#endif /* PACKET_H_ */
