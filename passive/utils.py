#!/usr/bin/env python3

import os
import sys
import subprocess
import shlex
import time
import signal
import json
import usb.core
import itertools
from datetime import datetime
import shutil


# Description: Determines if a program is active using ps aux
# Input: The name of the program to check
# Output: True (if program running) or False (otherwise)
def check_if_active(prog):
	prog_status = subprocess.run(shlex.split('ps aux'), 
		stdout=subprocess.PIPE, 
		stderr=subprocess.PIPE,
		text=True,
	)

	return True if prog in prog_status.stdout else False


# Description: Finds the PID of a process
# Input: The name of the process
# Output: A list of PIDs for the process
def prog_pids(prog):
	pyth_pro = subprocess.run(["pidof", prog], 
		stdout=subprocess.PIPE, 
		stderr=subprocess.PIPE,
		text=True,
	)

	return pyth_pro.stdout.strip("\n").split(" ")


# Description: Finds the PID of a python process
# Input: The name of the process
# Output: A list of PIDs for the process
def find_pyth_pids(pidlist, process_name):
	prog_status = subprocess.run(shlex.split('ps aux'), 
		stdout=subprocess.PIPE, 
		stderr=subprocess.PIPE,
		text=True,
	)

	for line in prog_status.stdout.split("\n"):
		if process_name in line:
			line_pid = list(itertools.filterfalse(lambda x: x == '', line.split(" ")))[1]
			if line_pid in pidlist:
				return int(line_pid)

	return -1


# Description: Kills a process if active
# Input: The name of the process
def stop_prog(prog):
	while check_if_active(prog):
		os.kill(int(prog_pids(prog)[0]), signal.SIGINT)
		time.sleep(1)


# Description: Kills a python process if active
# Input: The name of the process
def stop_py_prog(prog, command):
	if check_if_active(prog):
		py_pid = find_pyth_pids(prog_pids("python3"), command)

		if py_pid != -1:
			while find_pyth_pids(prog_pids("python3"), command) != -1:
				os.kill(py_pid, signal.SIGINT)
				time.sleep(1)



# Description: Looks for an SDR that can be used
# Output: The name of the selected SDR
def find_SDR():
	scan_dev = {}

	dev = usb.core.find(find_all=True)

	for cfg in dev:
		if hex(cfg.idVendor) == '0xbda' and hex(cfg.idProduct) == '0x2838':
			scan_dev[1] = "RTL-SDR"
			print("[+] RTL-SDR detected")
		elif hex(cfg.idVendor) == '0x1d50' and hex(cfg.idProduct) == '0x6089':
			scan_dev[0] = "hackrf"
			print("[+] HackRF detected")
		elif hex(cfg.idVendor) == '0x2cf0' and hex(cfg.idProduct) == '0x5250':
			scan_dev[2] = "bladerf"
			print("[+] BladeRF detected")

	keys = list(scan_dev.keys())
	if len(keys) != 0:
		keys.sort()
		print(f"[+] Using {scan_dev[keys[0]]}")
		return scan_dev[keys[0]]

	return ""


# Description: Open BTS info json file
def open_json(filename):
	with open(filename) as f:
		file_data = json.load(f)

	return file_data

# Description: Write BTS info to json file
def write_json(filename, data):
	json_object = json.dumps(data, indent=4)

	with open(filename, "w") as f:
		f.write(json_object)