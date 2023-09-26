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
make install && ldconfig
```
## Usage
Requires root access.

To show the help message:
```bash
./twamp-light-client -h
./twamp-light-server -h
```
### starting systemd service
```bash
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable twamp-light-server.service
sudo systemctl start twamp-light-server.service
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

### Example outputs

These are measurements taken from the Hilton Union Square in San Francisco, over the IETF-provided network, to an AWS server in Frankfurt during the 117th IETF.

Ethernet:
Total samples: 10000
| Metric   | RTT        | FWD        | BWD        |
|----------|------------|------------|------------|
| mean     | 0.148550 s | 0.074235 s | 0.074312 s |
| median   | 0.148495 s | 0.074226 s | 0.074259 s |
| min      | 0.148069 s | 0.074000 s | 0.063080 s |
| max      | 0.165831 s | 0.085664 s | 0.091504 s |
| std      | 0.000541 s | 0.000163 s | 0.000537 s |
| variance | 0.000000 s | 0.000000 s | 0.000000 s |
| p95      | 0.148797 s | 0.074341 s | 0.074480 s |
| p99      | 0.150078 s | 0.074420 s | 0.075675 s |
| p99.9    | 0.157121 s | 0.075416 s | 0.082899 s |


 WiFi:
 Total samples: 10000
| Metric   | RTT        | FWD        | BWD        |
|----------|------------|------------|------------|
| mean     | 0.160776 s | 0.081326 s | 0.079446 s |
| median   | 0.158713 s | 0.079425 s | 0.078142 s |
| min      | 0.153002 s | 0.076112 s | 0.073728 s |
| max      | 0.259217 s | 0.181256 s | 0.146672 s |
| std      | 0.007430 s | 0.006159 s | 0.003780 s |
| variance | 0.000055 s | 0.000038 s | 0.000014 s |
| p95      | 0.174096 s | 0.092098 s | 0.086615 s |
| p99      | 0.190109 s | 0.105803 s | 0.093184 s |
| p99.9    | 0.220209 s | 0.136611 s | 0.111531 s |
