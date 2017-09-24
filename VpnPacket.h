#ifndef VPNPACKET_H_
#define VPNPACKET_H_


#include <cstdint>
#include <string>


#pragma pack(1)                                             // disable alignment of struct members


class VpnPacket {
    public:
    uint16_t        magic;
    uint8_t         msg_type;
    uint16_t        msg_size;

    static constexpr auto MAGIC = 0x484B;
    static constexpr auto MSG_TYPE_HELLO = 10;

    VpnPacket(uint8_t msg_type, uint16_t msg_size);
    void print() const;
    ~VpnPacket();
};


class VpnPacketHello: public VpnPacket {
    public:
    char            message[16];

    VpnPacketHello(const std::string& message);
    ~VpnPacketHello();
};


#endif /* VPNPACKET_H_ */
