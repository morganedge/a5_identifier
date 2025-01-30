#!/usr/bin/env python3

import pyshark
import argparse
import os
import sys
from datetime import datetime
import time
import utils

parser = argparse.ArgumentParser(
	prog='A5 counter', 
	description='Counts the occurrence of the versions of A5 used in a network'
	)
parser.add_argument('-f', '--freq', help="frequency of the BTS", type=float, required=True)
parser.add_argument('-r', '--runtime', help="time in minutes to obtain sys info", type=int, required=False, default=10)
args = parser.parse_args()


def print_summary():
	global a5_1_count
	global a5_2_count
	global a5_3_count
	global a5_4_count
	global a5_count

	if a5_count > 0:
		for i in range(0, 8):
			print('\033[1A', end='\x1b[2K')

	if a5_count > 0:
		print(f"\n{' '*4}A5 Count")
		print(f"{' '*4}{'='*18}")
		print(f"{' '*4}Total: {a5_count}")
		print(f"{' '*4}A5/1: {a5_1_count} ({round((a5_1_count/a5_count)*100, 2)}%)")
		print(f"{' '*4}A5/2: {a5_2_count} ({round((a5_2_count/a5_count)*100, 2)}%)")
		print(f"{' '*4}A5/3: {a5_3_count} ({round((a5_3_count/a5_count)*100, 2)}%)")
		print(f"{' '*4}A5/4: {a5_4_count} ({round((a5_4_count / a5_count) * 100, 2)}%)")



scan_dev = utils.find_SDR()

if scan_dev == "":
	sys.exit("[!] No suitable SDR receivers detected")
if scan_dev == "RTL-SDR" and args.freq > 1750:
	sys.exit("[!] RTL-SDR unable to scan this frequency")


print(f"    [+] Running scan on {args.freq}M for {args.runtime} minutes")
os.system(f"gnome-terminal -- grgsm_livemon_headless --args={scan_dev} -f {args.freq}M")
print("\n\n\n\n\n\n\n")


start_test = datetime.now()
start_time = time.time()
last_detection_time = time.time()
timeout = 30

bts_check = None
bts_data = {}
a5_info = []

a5_1_count, a5_2_count, a5_3_count, a5_4_count, a5_count = 0, 0, 0, 0, 0

try:
	capture = pyshark.LiveCapture(interface='lo', bpf_filter=f'udp and port 4729')

	os.system(f"gnome-terminal -- python3 send_dummy_data.py -t {(args.runtime * 60) + 15}")

	for packet in capture.sniff_continuously():
		if (time.time() - last_detection_time) >= timeout or (time.time() - start_time) >= (args.runtime * 60):
			print_summary()
			break

		layer_names = []
		for layers in packet.layers:
			layer_names.append(layers.layer_name)

		if 'gsmtap' not in layer_names or packet['gsmtap'].has_field('version_invalid'):
			continue

		last_detection_time = time.time()

		# check CID in Sys3 to determine if BTS file already exists
		if not bts_check:
			if packet[-1].layer_name == 'gsm_a.ccch':
				dtap_type = int(packet['gsm_a.ccch'].get_field('gsm_a.dtap.msg_rr_type'), 16)
				if dtap_type == 0x1b:
					mcc = packet['gsm_a.ccch'].get_field('e212.lai.mcc')
					mnc = packet['gsm_a.ccch'].get_field('e212.lai.mnc')
					lac = int(packet['gsm_a.ccch'].get_field('gsm_a.lac'), 16)
					cid = int(packet['gsm_a.ccch'].get_field('gsm_a.bssmap.cell_ci'), 16)

					bts_check = True

					if os.path.exists(f"./scans/{mcc}_{mnc}_{lac}_{cid}_{str(args.freq).replace('.', '_')}.json"):
						bts_data = utils.open_json(f"./scans/{mcc}_{mnc}_{lac}_{cid}_{str(args.freq).replace('.', '_')}.json")
						a5_info = bts_data["A5 count"]
					else:
						bts_data = {"MCC": mcc, "MNC": mnc, "LAC": lac, "CID": cid, "Freq": args.freq}
						bts_data["A5 count"] = {}

			
			if bts_check is None:
				continue
			else:
				timeout = 360


		if packet[-1].layer_name != 'gsm_a.dtap':
			continue

		if packet['gsm_a.dtap'].has_field('gsm_a_dtap_msg_rr_type') or packet['gsm_a.dtap'].has_field('msg_rr_type'):
			dtap_type = int(packet['gsm_a.dtap'].get_field('gsm_a.dtap.msg_rr_type'), 16)

			if dtap_type == 0x35:
				a5_count += 1
				algo = packet['gsm_a.dtap'].get_field('gsm_a.rr.algorithm_identifier')

				if int(algo, 16) == 0:
					a5_1_count += 1
				elif int(algo, 16) == 1:
					a5_2_count += 1
				elif int(algo, 16) == 2:
					a5_3_count += 1
				elif int(algo, 16) == 3:
					a5_4_count += 1

				print_summary()
except KeyboardInterrupt:
	capture.clear()
	capture.close()
except Exception as e:
	print(f"[!] Error Message: {e}")

end_test = datetime.now()

print_summary()
utils.stop_py_prog("grgsm_livemon_headless", f"grgsm_livemon_headless --args={scan_dev} -f {args.freq}M")
utils.stop_py_prog("send_dummy_data", 'send_dummy_data.py')

if a5_count > 0:
	a5_usage = {"Start Time": start_test.strftime("%Y/%m/%d %H:%M:%S"), "A5 count": a5_count,
				"A5/1 count": a5_1_count, "A5/2 count": a5_2_count, "A5/3 count": a5_3_count, "A5/4 count": a5_4_count,
				"End Time": end_test.strftime("%Y/%m/%d %H:%M:%S"), "Total Time": f"{end_test - start_test}"}
	a5_info.append(a5_usage)
	bts_data["A5 count"] = a5_info

	utils.write_json(f"./scans/{mcc}_{mnc}_{lac}_{cid}_{str(args.freq).replace('.', '_')}.json", bts_data)