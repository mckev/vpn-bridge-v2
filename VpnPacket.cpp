#include <cstring>                                          // strncat
#include <iostream>
#include "VpnPacket.h"


VpnPacket::VpnPacket(uint8_t msg_type, uint16_t msg_size)
    : magic{MAGIC}, msg_type{msg_type}, msg_size{msg_size} {
}

void VpnPacket::print() const {
    for (unsigned int i = 0; i < msg_size + sizeof(VpnPacket); i++) {
        char ch = ((char*) this)[i];
        std::cout << i << ": " << (isprint(ch) ? ch : ' ') << " " << (int) ch << std::endl;
    }
}

VpnPacket::~VpnPacket() {
}


VpnPacketHello::VpnPacketHello(const std::string& message)
    : VpnPacket(MSG_TYPE_HELLO, sizeof(VpnPacketHello) - sizeof(VpnPacket)) {
    // Copy the content of message into Hello packet
    this->message[0] = '\0';
    strncat(this->message, message.c_str(), sizeof(this->message) - 1);
}

VpnPacketHello::~VpnPacketHello() {
}
