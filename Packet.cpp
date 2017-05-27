#include <iomanip>
#include <iostream>
#include "Packet.h"


void Eth::print_eth() const {
    std::cout << "Ethernet Header" << std::endl;
    std::cout << "   |-Destination Address  : " << std::hex
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[0] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[1] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[2] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[3] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[4] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_dest[5] << std::dec << std::endl;
    std::cout << "   |-Source Address       : " << std::hex
                                                << std::setfill('0') << std::setw(2) << (int) h_source[0] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_source[1] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_source[2] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_source[3] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_source[4] << ":"
                                                << std::setfill('0') << std::setw(2) << (int) h_source[5] << std::dec << std::endl;
    std::cout << "   |-Protocol             : " << h_proto << std::endl;
}


void Ip::print_ip() const {
    std::cout << "IP Header" << std::endl;
    std::cout << "   |-IP Version           : " << (int) version << std::endl;
    std::cout << "   |-IP Header Length     : " << (int) ihl << " dwords or " << ihl*4 << " bytes" << std::endl;
    if (ihl != 5) {
        std::cout << "                            (IHL > 5: IP Options exists)" << std::endl;
    }
    std::cout << "   |-Type Of Service      : " << (int) tos << std::endl;
    std::cout << "   |-IP Total Length      : " << ntohs(tot_len) << " bytes (Size of Packet)" << std::endl;
    std::cout << "   |-Identification       : " << ntohs(id) << std::endl;
    std::cout << "   |-TTL                  : " << (int) ttl << std::endl;
    std::cout << "   |-Protocol             : " << (int) protocol << std::endl;
    std::cout << "   |-Checksum             : " << ntohs(check) << std::endl;
    std::cout << "   |-Source IP            : " << (int) *(((uint8_t*) &saddr) + 0) << "."
                                                << (int) *(((uint8_t*) &saddr) + 1) << "."
                                                << (int) *(((uint8_t*) &saddr) + 2) << "."
                                                << (int) *(((uint8_t*) &saddr) + 3) << std::endl;
    std::cout << "   |-Destination IP       : " << (int) *(((uint8_t*) &daddr) + 0) << "."
                                                << (int) *(((uint8_t*) &daddr) + 1) << "."
                                                << (int) *(((uint8_t*) &daddr) + 2) << "."
                                                << (int) *(((uint8_t*) &daddr) + 3) << std::endl;
}
