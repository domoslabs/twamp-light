#!/bin/bash
VER=$1
mkdir -p twamp-light-$VER/usr/local/bin
mkdir -p twamp-light-$VER/lib/systemd/system
mkdir -p twamp-light-$VER/usr/local/lib
mkdir twamp-light-$VER/DEBIAN
cp ../debian/control.txt twamp-light-$VER/DEBIAN/control
cp ../debian/triggers.txt twamp-light-$VER/DEBIAN/triggers
cp ../debian/postinst.sh twamp-light-$VER/DEBIAN/postinst

sed -i '/Version: 1.0.0/c\Version: '"$VER"'' twamp-light-$VER/DEBIAN/control

cp twamp-light-client twamp-light-$VER/usr/local/bin
cp qoo-c/src/libqoo.so twamp-light-$VER/usr/local/lib/libqoo.so
cp twamp-light-server twamp-light-$VER/usr/local/bin
cp ../systemd/twamp-light-server.service twamp-light-$VER/lib/systemd/system

dpkg-deb --build twamp-light-$VER
