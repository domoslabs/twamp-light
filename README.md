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