#!/bin/bash
stdbuf -o0 ./twamp-light-server -P 4200 &> server_output.txt &
server_pid=$!
sleep 1
stdbuf -o0 ./twamp-light-client localhost:4200 &> client_output.txt
sleep 1
kill $server_pid

# Check if the server output is correct

# Define the expected header
expected_header="Time,IP,Snd#,Rcv#,SndPort,RscPort,FW_TTL,SndTOS,FW_TOS,IntD,FWD,PLEN,"

# Get the actual header
header=$(head -n 1 server_output.txt)

# Compare the headers
if [[ "$header" != "$expected_header" ]]; then
  echo "Header mismatch"
  exit 1
fi

# Use awk to check the field count of each row, excluding the header row
awk -F, 'NR>1 && NF!=12 {print "Field count mismatch on line", NR; exit 1}' server_output.txt

# Use awk to check the IP field of each row, excluding the header row
awk -F, 'NR>1 && $2!="127.0.0.1" {print "IP mismatch on line", NR; exit 1}' server_output.txt

# Use awk to check if the Time field is numeric, excluding the header row
awk -F, 'NR>1 && $1 !~ /^[0-9]+$/ {print "Non-numeric Time value on line", NR; exit 1}' server_output.txt

# Use awk to check if the values in the PLEN field are within a specific range, excluding the header row
awk -F, 'NR>1 && ($12 < 40 || $12 > 1500) {print "PLEN value out of range on line", NR; exit 1}' server_output.txt


# Check if the client output is correct

# Define the expected header
expected_header="Time,IP,Snd#,Rcv#,SndPort,RscPort,Sync,FW_TTL,SW_TTL,SndTOS,FW_TOS,SW_TOS,RTT,IntD,FWD,BWD,PLEN,LOSS"

# Get the actual header
header=$(head -n 1 client_output.txt)

# Compare the headers
if [[ "$header" != "$expected_header" ]]; then
  echo "Header mismatch"
  exit 1
fi

# Validate the number of fields in each row
awk -F, 'NR>1 && NF!=18 {print "Field count mismatch on line", NR; exit 1}' client_output.txt

# Validate the IP field values, excluding the header row
awk -F, 'NR>1 && $2!="127.0.0.1" {print "IP mismatch on line", NR; exit 1}' client_output.txt

# Check if the Time field is numeric, excluding the header row
awk -F, 'NR>1 && $1 !~ /^[0-9]+$/ {print "Non-numeric Time value on line", NR; exit 1}' client_output.txt

# Validate the range of values in the PLEN field, excluding the header row
awk -F, 'NR>1 && ($17 < 40 || $17 > 1500) {print "PLEN value out of range on line", NR; exit 1}' client_output.txt

# Validate that the LOSS field is numeric and non-negative, excluding the header row
awk -F, 'NR>1 && ($18 !~ /^[0-9]+$/ || $18 < 0) {print "Invalid LOSS value on line", NR; exit 1}' client_output.txt
