#!/usr/bin/env python3

import socket
import time
from datetime import datetime
import argparse

parser = argparse.ArgumentParser(
	prog='Send Dummy', 
	description='Send random data to port 4729 so pyshark can stop'
	)
parser.add_argument('-t', '--time', help="time in seconds to send dummy data", type=int, required=True)
args = parser.parse_args()

dummy_data = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('127.0.0.2', 4729)

start_time = datetime.now()

try:
	while (datetime.now() - start_time).total_seconds() < args.time:
		print(f"> ({(datetime.now() - start_time).total_seconds():.2f}) Sending data")
		dummy_data.sendto("dummy data".encode(), server_address)
		time.sleep(10)
finally:
	dummy_data.close()
