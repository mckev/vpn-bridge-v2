#include "pch.h"
#include "VpnPacket.h"


TEST(VpnPacketTestHello, CreateVpnPacketHelloWithShortMessage) {
	VpnPacketHello hello{ "Hello, world!" };
	std::vector<uint8_t> expected = {
		0x4b, 0x48, 0x0a, 0x0d, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c,
		0x64, 0x21
	};
	uint8_t* hello_pointer = reinterpret_cast<uint8_t*>(&hello);
	EXPECT_EQ(expected, std::vector<uint8_t>(hello_pointer, hello_pointer + expected.size()));
}


TEST(VpnPacketTestHello, CreateVpnPacketHelloWithLongMessage) {
	VpnPacketHello hello{ "Hello, world! How are you?" };
	std::vector<uint8_t> expected = {
		0x4b, 0x48, 0x0a, 0x10, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c,
		0x64, 0x21, 0x20, 0x48, 0x6f
	};
	uint8_t* hello_pointer = reinterpret_cast<uint8_t*>(&hello);
	EXPECT_EQ(expected, std::vector<uint8_t>(hello_pointer, hello_pointer + expected.size()));
}
