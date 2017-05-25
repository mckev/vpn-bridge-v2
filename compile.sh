#!/bin/sh

# Pre-requisites:
#    yum install -y gcc-c++
#    yum install glibc-devel.i686

machine=`uname -m`
if [ "$machine" == "i686" -o "$machine" == "x86_64" ]; then
    echo "i686"
    g++ -std=c++11 -Wall -m32 -O3 -o Packet.o   -c Packet.cpp

elif [ "$machine" == "armv6l" ]; then
    echo "armv6l"

else
    echo "Unsupported processor $machine"
fi
