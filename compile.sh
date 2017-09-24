#!/bin/sh

CXXFLAGS="-std=c++11 -Wall -O3"

machine=`uname -m`
if [ "$machine" = "x86_64" ]; then
    # Pre-requisites:
    #    yum install -y gcc-c++
    CXXFLAGS="$CXXFLAGS -m64"

elif [ "$machine" = "armv6l" ]; then
    CXXFLAGS="$CXXFLAGS"

else
    echo "Unsupported processor $machine"
    exit 1
fi

echo "Processor: $machine"
echo "CXXFLAGS: $CXXFLAGS"
echo "Compiling..."
rm -f Packet.o
rm -f VpnPacket.o
rm -f vclient.o
rm -f vclient
g++ $CXXFLAGS -o Packet.o      -c Packet.cpp
g++ $CXXFLAGS -o VpnPacket.o   -c VpnPacket.cpp
g++ $CXXFLAGS -o vclient.o     -c vclient.cpp
g++ $CXXFLAGS -o vclient       Packet.o VpnPacket.o vclient.o
echo "Done."
