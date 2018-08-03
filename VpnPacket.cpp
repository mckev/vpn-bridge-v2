#include <cstring>                                          // strncat
#include <iostream>
#include "VpnPacket.h"


VpnPacket::VpnPacket(uint8_t msg_type, uint16_t msg_size)
	: msg_type{ msg_type }, msg_size{ msg_size } {
}


VpnPacket::VpnPacket(uint8_t msg_type)
	: VpnPacket(msg_type, 0) {
}


void VpnPacket::print() const {
	for (unsigned int i = 0; i < sizeof(VpnPacket) + msg_size; i++) {
		char ch = ((char*)this)[i];
		std::cout << i << ": " << (isprint(ch) ? ch : ' ') << " " << (int)ch << std::endl;
	}
}


VpnPacketHello::VpnPacketHello(const std::string& message) : VpnPacket(MSG_TYPE_HELLO) {
	strncpy(this->message, message.c_str(), sizeof(this->message));
	msg_size = strnlen(this->message, sizeof(this->message));
}
