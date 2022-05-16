# Twamp Light

## Installation
Clone the repo and all its submodules:
```bash
git clone --recurse-submodules https://github.com/domoslabs/twamp-light.git 
```
Then using cmake:
```bash
mkdir build
cd build
cmake ..
make
```
This outputs a client and a server executable.

Optional:
```bash
make install
```
## Usage
Requires root access.

To show the help message:
```bash
./twamp-light-client -h
./twamp-light-server -h
```
## Details
### Format and protocol
The packets are formatted according to [RFC5357](https://datatracker.ietf.org/doc/html/rfc5357#page-23). 
If time synchronization is enabled (default behaviour, see help for how to disable), the timestamp field (64bit) will be split into timestamp (32bit)+timesync data (32bit),
which breaks the protocol and therefore becomes incompatible with other TWAMP Light implementations.

### Sampling
All the arguments that take in multiple values, such as payload size and delay, 
are sampled uniformly using Marsenne Twister when the client crafts a packet.
The server simply reflects packets, and there is therefore no sampling of any sort on the server.