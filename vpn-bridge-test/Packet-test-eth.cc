#include "pch.h"
#include "Packet.h"


static uint8_t packet[14] = {
	0x1c, 0x1b, 0x0d, 0x9d, 0x61, 0xfd, 0x08, 0x00, 0x27, 0xc4, 0xc6, 0xc6, 0x08, 0x00
};

TEST(PacketTestEth, ParseEthPacketCorrectly) {
	Eth* eth = (Eth*)packet;
	EXPECT_EQ(std::string("1c:1b:0d:9d:61:fd"), Eth::mac_addr_to_str(eth->h_dest));
	EXPECT_EQ(std::string("08:00:27:c4:c6:c6"), Eth::mac_addr_to_str(eth->h_source));
	EXPECT_EQ(Eth::ETH_P_IP, ntohs(eth->h_proto));
}
