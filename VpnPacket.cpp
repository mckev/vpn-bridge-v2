#include <cstring>
#include <iostream>
#include "VpnPacket.h"


VpnPacketHello::VpnPacketHello(const std::string& message)
    : VpnPacket(MSG_TYPE_HELLO, sizeof(VpnPacketHello) - sizeof(VpnPacket)) {
    // Copy the content of message into Hello packet
    this->message[0] = '\0';
    strncat(this->message, message.c_str(), sizeof(this->message) - 1);
}


void VpnPacketHello::print() const {
    for (int i = 0; i < (int) sizeof(VpnPacketHello); i++) {
        char ch = ((char*) this)[i];
        std::cout << i << ": " << (isprint(ch) ? ch : ' ') << " " << (int) ch << std::endl;
    }
}
