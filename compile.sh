#!/bin/sh

machine=`uname -m`
if [ "$machine" = "x86_64" ]; then
    # Pre-requisites:
    #    yum install -y gcc-c++
    echo "Processor: x86_64"
    CXXFLAGS="-m64"
elif [ "$machine" = "armv6l" ]; then
    echo "Processor: armv6l"
    CXXFLAGS=""
else
    echo "Unsupported processor $machine"
    exit 1
fi

echo "CXXFLAGS: $CXXFLAGS"
echo "Compiling..."
rm -f Packet.o
rm -f vclient.o
rm -f vclient
g++ -std=c++11 -Wall $CXXFLAGS -O3 -o Packet.o   -c Packet.cpp
g++ -std=c++11 -Wall $CXXFLAGS -O3 -o vclient.o  -c vclient.cpp
g++ -std=c++11 -Wall $CXXFLAGS -O3 -o vclient    Packet.o vclient.o
echo "Done."
