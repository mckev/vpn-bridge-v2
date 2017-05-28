#include <cassert>
#include <cstring>
#include <iostream>
#include "Packet.h"


int open_raw_socket() {
    static const int AF_PACKET      = 17;
    static const int PF_PACKET      = AF_PACKET;
    static const int SOCK_RAW       = 3;
    static const int ETH_P_ALL      = 0x0003;
    int sd_incoming = (int) socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    return sd_incoming;
}


int main() {
    int sd_incoming = open_raw_socket();
    if (sd_incoming == -1) {
        std::cerr << "Error while opening raw socket: socket() error " << errno << ": " << strerror(errno) << std::endl;
        exit(1);
    }
    std::cout << "Listening on the wire..." << std::endl;
    while (true) {
        // Raw packet capture
        uint8_t buffer[Ip::IP_MAXPACKET];
        socklen_t size;
        struct sockaddr_in  from;
        socklen_t           fromlen = sizeof(from);
        size = recvfrom(sd_incoming, (char*) buffer, sizeof(buffer), 0, (struct sockaddr*) &from, &fromlen);
        std::cout << "Receiving " << size << " bytes" << std::endl;

        // There are two possible cases:
        //    1. In Hostgator, we receive IP packets (layer 3).
        //    2. In Linux box, we receive DataLink packets (layer 2).
        // So it is better to use IP packets since it works everywhere.
        Ip* ip;

        // Case Linux
        {
            // Layer 2: Ethernet packet
            Eth* eth = (Eth*) buffer;
            eth->print_eth();
            if (ntohs(eth->h_proto) != Eth::ETH_P_IP) continue;

            // Layer 3: IP packet
            ip = (Ip*) (buffer + sizeof(Eth));
            ip->print_ip();
            size -= sizeof(Eth);
        }
    }
    return 0;
}
