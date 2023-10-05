#!/bin/bash

# Run Valgrind on the server and client, capturing the output
valgrind --leak-check=full --log-file=server_valgrind_output.txt ./twamp-light-server -P 4200 &> /dev/null &
server_pid=$!

sleep 1  # Allow the server to start up (adjust sleep duration as needed)

valgrind --leak-check=full --log-file=client_valgrind_output.txt ./twamp-light-client localhost:4200 &> /dev/null  &
client_pid=$!

# Wait for the client and server to finish
wait $client_pid
kill $server_pid  # In case the server is still running

parse_valgrind_output() {
  local output_file=$1

  # Check for memory leaks
  if grep -q "definitely lost: 0 bytes in 0 blocks\|All heap blocks were freed -- no leaks are possible" "$output_file"; then
    echo "No memory leaks detected in $output_file"
  else
    echo "Memory leak detected in $output_file"
    grep "definitely lost:" "$output_file"
    exit 1
  fi

  # Check for invalid read/write operations
  if grep -q "Invalid read\|Invalid write" "$output_file"; then
    echo "Invalid read/write detected in $output_file"
    grep "Invalid read\|Invalid write" "$output_file"
    exit 1
  fi

  # Check for other errors
  if grep -q "ERROR SUMMARY: 0 errors from 0 contexts" "$output_file"; then
    echo "No other errors detected in $output_file"
  else
    echo "Other errors detected in $output_file"
    grep "ERROR SUMMARY:" "$output_file"
    exit 1
  fi
}

parse_valgrind_output server_valgrind_output.txt
parse_valgrind_output client_valgrind_output.txt
