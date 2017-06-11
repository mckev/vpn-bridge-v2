#include <cassert>
#include <cstring>
#include <iostream>
#include "Packet.h"


int open_raw_socket() {
    static constexpr auto AF_PACKET = 17;
    static constexpr auto PF_PACKET = AF_PACKET;
    static constexpr auto SOCK_RAW  = 3;
    static constexpr auto ETH_P_ALL = 0x0003;
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
        std::cout << std::endl
                  << "Receiving " << size << " bytes" << std::endl;

        // There are two possible cases:
        //    1. In Hostgator, we receive IP packets (layer 3).
        //    2. In Linux box, we receive DataLink packets (layer 2).
        // So it is better to use IP packets since it works everywhere.
        Ip* ip;

        // Case Linux
        {
            // Layer 2: Ethernet packet
            Eth* eth = (Eth*) buffer;
            eth->print();
            if (ntohs(eth->h_proto) != Eth::ETH_P_IP) continue;

            // Layer 3: IP packet
            ip = (Ip*) ((uint8_t*) buffer + sizeof(Eth));
            size -= sizeof(Eth);
        }
        ip->print();
        {
            // Verify that our IP checksum algorithm is correct
            uint16_t original_checksum = ip->check;
            ip->check = 0;
            ip->check = ip->checksum();
            assert(ip->check == original_checksum);
        }

        // Layer 4
        switch (ip->protocol) {
            case Ip::IPPROTO_TCP:
                {
                    Tcp* tcp = (Tcp*) ((uint8_t*) ip + (ip->ihl * 4));
                    tcp->print();
                    {
                        // Verify that our TCP checksum algorithm is correct
                        // How to disable checksum offloading: ethtool -K eth0 rx off tx off   (https://stackoverflow.com/questions/15538786/how-is-tcps-checksum-calculated-when-we-use-tcpdump-to-capture-packets-which-we)
                        uint16_t original_checksum = tcp->check;
                        tcp->check = 0;
                        tcp->check = tcp->checksum(ntohs(ip->tot_len) - (ip->ihl * 4), ip->saddr, ip->daddr);
                        assert(tcp->check == original_checksum);
                    }
                }
                break;

            case Ip::IPPROTO_UDP:
                {
                    Udp* udp = (Udp*) ((uint8_t*) ip + (ip->ihl*4));
                    udp->print();
                    {
                        // Verify that our UDP checksum algorithm is correct
                        uint16_t original_checksum = udp->check;
                        udp->check = 0;
                        udp->check = udp->checksum(ntohs(ip->tot_len) - (ip->ihl * 4), ip->saddr, ip->daddr);
                        assert(udp->check == original_checksum);
                    }
                }
                break;

            case Ip::IPPROTO_ICMP:
                {
                    Icmp* icmp = (Icmp*) ((uint8_t*) ip + (ip->ihl*4));
                    icmp->print();
                    {
                        // Verify that our ICMP checksum algorithm is correct
                        uint16_t original_checksum = icmp->check;
                        icmp->check = 0;
                        icmp->check = icmp->checksum(ntohs(ip->tot_len) - (ip->ihl * 4));
                        assert(icmp->check == original_checksum);
                    }
                }
                break;

            default:
                // Ignore non TCP, UDP or ICMP data
                continue;
        }
    }
    return 0;
}
