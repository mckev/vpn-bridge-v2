#include <cstring>                                          // strncpy, strnlen
#include <string>
#include "Packet.h"
#include "VpnPacket.h"


// --- BASE ---

VpnPacket::VpnPacket(uint8_t msg_type, uint16_t msg_size) : msg_type{ msg_type }, msg_size{ msg_size } {
}

VpnPacket::VpnPacket(uint8_t msg_type) : VpnPacket(msg_type, 0) {
}

int VpnPacket::header_len() const
{
	return sizeof(VpnPacket);
}

int VpnPacket::total_len() const
{
	return header_len() + msg_size;
}

void VpnPacket::print_raw() const {
	Util::print_raw(reinterpret_cast<const uint8_t*>(this), total_len());
}




// --- HELLO ---

VpnPacketHello::VpnPacketHello(const std::string& message) : VpnPacket(MsgType::HELLO) {
	strncpy(this->message, message.c_str(), sizeof(this->message));
	msg_size = strnlen(this->message, sizeof(this->message));
}
