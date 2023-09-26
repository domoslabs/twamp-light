#!/bin/bash
VER=$1
mkdir -p twamp-light-$VER/usr/local/bin
mkdir -p twamp-light-$VER/lib/systemd/system
mkdir twamp-light-$VER/DEBIAN
cp ../debian/control.txt twamp-light-$VER/DEBIAN/control

sed -i '/Version: 1.0.0/c\Version: '"$VER"'' twamp-light-$VER/DEBIAN/control


cp twamp-light-client twamp-light-$VER/usr/local/bin
cp twamp-light-server twamp-light-$VER/usr/local/bin
cp ../systemd/twamp-light-server.service twamp-light-$VER/lib/systemd/system

dpkg-deb --build twamp-light-$VER
