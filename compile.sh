#!/bin/sh

machine=`uname -m`
if [ "$machine" = "x86_64" ]; then
    # Pre-requisites:
    #    yum install -y gcc-c++
    CXXFLAGS="-m64"

elif [ "$machine" = "armv6l" ]; then
    CXXFLAGS=""

else
    echo "Unsupported processor $machine"
    exit 1
fi

echo "Processor: $machine"
echo "CXXFLAGS: $CXXFLAGS"
echo "Compiling..."
rm -f Packet.o
rm -f vclient.o
rm -f vclient
g++ -std=c++11 -Wall -O3 $CXXFLAGS -o Packet.o   -c Packet.cpp
g++ -std=c++11 -Wall -O3 $CXXFLAGS -o vclient.o  -c vclient.cpp
g++ -std=c++11 -Wall -O3 $CXXFLAGS -o vclient    Packet.o vclient.o
echo "Done."
