#!/bin/sh

# Pre-requisites:
#    yum install -y gcc-c++

machine=`uname -m`
if [ "$machine" == "x86_64" ]; then
    echo "x86_64"
    rm -f Packet.o
    rm -f vclient.o
    rm -f vclient
    g++ -std=c++11 -Wall -m64 -O3 -o Packet.o   -c Packet.cpp
    g++ -std=c++11 -Wall -m64 -O3 -o vclient.o  -c vclient.cpp
    g++ -std=c++11 -Wall -m64 -O3 -o vclient    Packet.o vclient.o

elif [ "$machine" == "armv6l" ]; then
    echo "armv6l"

else
    echo "Unsupported processor $machine"
fi
