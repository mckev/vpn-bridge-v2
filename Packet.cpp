#include <cassert>
#include <iomanip>
#include <iostream>
#include "Packet.h"


static uint16_t calculate_checksum(const void* buffer, int len, int proto, uint32_t src_addr, uint32_t dest_addr) {
    // Ref:
    // IP: http://www.pdbuchan.com/rawsock/tcp4.c
    // TCP: http://minirighi.sourceforge.net/html/tcp_8c-source.html
    // UDP: http://minirighi.sourceforge.net/html/udp_8c-source.html

    uint16_t* w = (uint16_t*) buffer;
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
        sum += *((uint8_t*) w);
    }

    // Add the pseudo headers
    if (proto != 0) {
        uint16_t* ip_src = (uint16_t*) &src_addr;
        uint16_t* ip_dst = (uint16_t*) &dest_addr;
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
    return (uint16_t) ~sum;
}


void Eth::print() const {
    std::cout << "Ethernet Header" << std::endl
              << "   |-Destination Address  : " << std::hex
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[0] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[1] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[2] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[3] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[4] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[5] << std::dec << std::endl
              << "   |-Source Address       : " << std::hex
                                                << std::setfill('0') << std::setw(2) << (int) h_source[0] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_source[1] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_source[2] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_source[3] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_source[4] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_source[5] << std::dec << std::endl
              << "   |-Protocol             : " << h_proto << std::endl;
}


void Ip::print() const {
    std::cout << "IP Header" << std::endl
              << "   |-IP Version           : " << (int) version << std::endl
              << "   |-IP Header Length     : " << (int) ihl << " dwords or " << ihl * 4 << " bytes" << std::endl;
    if (ihl != 5) {
        std::cout << "                            (IHL > 5: IP Options exists)" << std::endl;
    }
    std::cout << "   |-Type Of Service      : " << (int) tos << std::endl
              << "   |-IP Total Length      : " << ntohs(tot_len) << " bytes (Size of Packet)" << std::endl
              << "   |-Identification       : " << ntohs(id) << std::endl
              << "   |-TTL                  : " << (int) ttl << std::endl
              << "   |-Protocol             : " << (int) protocol << std::endl
              << "   |-Checksum             : " << ntohs(check) << std::endl
              << "   |-Source IP            : " << (int) *(((uint8_t*) &saddr) + 0) << "."
                                                << (int) *(((uint8_t*) &saddr) + 1) << "."
                                                << (int) *(((uint8_t*) &saddr) + 2) << "."
                                                << (int) *(((uint8_t*) &saddr) + 3) << std::endl
              << "   |-Destination IP       : " << (int) *(((uint8_t*) &daddr) + 0) << "."
                                                << (int) *(((uint8_t*) &daddr) + 1) << "."
                                                << (int) *(((uint8_t*) &daddr) + 2) << "."
                                                << (int) *(((uint8_t*) &daddr) + 3) << std::endl;
}


uint16_t Ip::checksum(const Ip* ip, int len) {
    // Set ip->check to 0 before calling this function
    assert(ip->check == 0);

    // len is usually 20 bytes
    return calculate_checksum(ip, len, 0, 0, 0);
}


void Tcp::print() const {
    std::cout << "TCP Header" << std::endl
              << "   |-Source Port          : " << ntohs(source) << std::endl
              << "   |-Destination Port     : " << ntohs(dest) << std::endl
              << "   |-Sequence Number      : " << ntohl(seq) << std::endl
              << "   |-Acknowledge Number   : " << ntohl(ack_seq) << std::endl
              << "   |-Header Length        : " << doff << " dwords or " << doff * 4 << " bytes" << std::endl;
    if (doff != 5) {
        std::cout << "                            (Data offset > 5: TCP Options exists)" << std::endl;
    }
    std::cout << "   |-Reserved             : " << res1 << std::endl
              << "   |-CWR Flag             : " << cwr << std::endl
              << "   |-ECN Flag             : " << ece << std::endl
              << "   |-Urgent Flag          : " << urg << std::endl
              << "   |-Acknowledgement Flag : " << ack << std::endl
              << "   |-Push Flag            : " << psh << std::endl
              << "   |-Reset Flag           : " << rst << std::endl
              << "   |-Synchronise Flag     : " << syn << std::endl
              << "   |-Finish Flag          : " << fin << std::endl
              << "   |-Window               : " << ntohs(window) << std::endl
              << "   |-Checksum             : " << ntohs(check) << std::endl
              << "   |-Urgent Pointer       : " << urg_ptr << std::endl;
}


uint16_t Tcp::checksum(const Tcp* tcp, int len, uint32_t src_addr, uint32_t dest_addr) {
    // Set tcp->check to 0 before calling this function
    assert(tcp->check == 0);
    
    return calculate_checksum(tcp, len, Ip::IPPROTO_TCP, src_addr, dest_addr);
}


void Udp::print() const {
    std::cout << "UDP Header" << std::endl
              << "   |-Source Port          : " << ntohs(source) << std::endl
              << "   |-Destination Port     : " << ntohs(dest) << std::endl
              << "   |-UDP Length           : " << ntohs(len) << std::endl
              << "   |-UDP Checksum         : " << ntohs(check) << std::endl;
}


uint16_t Udp::checksum(const Udp* udp, int len, uint32_t src_addr, uint32_t dest_addr) {
    // Set udp->check to 0 before calling this function
    assert(udp->check == 0);
    
    return calculate_checksum(udp, len, Ip::IPPROTO_UDP, src_addr, dest_addr);
}


void Icmp::print() const {
    std::cout << "ICMP Header" << std::endl
              << "   |-Type                 : " << (int) type << std::endl;
    if (type == Icmp::ICMP_TIME_EXCEEDED) {
        std::cout << "                            (TTL Expired)" << std::endl;
    } else if (type == Icmp::ICMP_ECHOREPLY) {
        std::cout << "                            (ICMP Echo Reply)" << std::endl;
    }
    std::cout << "   |-Code                 : " << (int) code << std::endl
              << "   |-Checksum             : " << ntohs(check) << std::endl;
}


uint16_t Icmp::checksum(const Icmp* icmp, int len) {
    // Set icmp->check to 0 before calling this function
    assert(icmp->check == 0);
    
    return calculate_checksum(icmp, len, 0, 0, 0);
}
