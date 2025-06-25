#!/usr/bin/env python3

import sys
import os
import argparse
import subprocess
import shlex
import signal
import re
import time
from datetime import datetime
import pyshark
from pyshark.capture.capture import StopCapture
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes


parser = argparse.ArgumentParser(
	prog='A5 check',
	description='Checks if an A5 algorithm is supported by a network (BTS)'
	)
parser.add_argument('-s', '--softsim', help="installation location of SoftSIM", required=False)
parser.add_argument('-o', '--osmocombb', help="installation location of OsmocomBB", required=False)
parser.add_argument('-O', '--osmocon', help="installation location of OsmocomBB osmocon", required=False)
parser.add_argument('-M', '--mobile', help="installation location of OsmocomBB mobile", required=False)
parser.add_argument('-F', '--firmware', help="installation location of firmware", required=False)
parser.add_argument('-m', '--model', help="osmocom-bb phone protocol", default="c123xor",
					choices=['c123', 'c123xor', 'c140', 'c140xor', 'c155', 'romload', 'mtk'], required=False)
parser.add_argument('-u', '--usbport', help="serial port connected to phone", default='/dev/ttyUSB0', required=False)
parser.add_argument('-i', '--input', help="analyse input file or files in directory", required=False)
parser.add_argument('-r', '--reset', action='store_true', help="set SIM card keys to default values (force re-auth)", required=False)
args = parser.parse_args()

work_area = os.getcwd()


def prog_pids(prog):
	prog_ids = subprocess.run(["pidof", prog], 
		stdout=subprocess.PIPE, 
		stderr=subprocess.PIPE,
		text=True,
	)

	return prog_ids.stdout.strip("\n").split(" ")


def process_cmd():
	pro_cmd = subprocess.run(shlex.split(f"ps aux"), 
		stdout=subprocess.PIPE, 
		stderr=subprocess.PIPE,
		text=True,
	)

	return pro_cmd.stdout


def reset_sim():
	cardtype = AnyCardType()
	cardrequest = CardRequest(timeout=10, cardType=cardtype)
	cardservice = cardrequest.waitforcard()
	cardservice.connection.connect()

	# select EF.KC
	cardservice.connection.transmit(toBytes(f"a0 a4 00 00 02 3f 00"))
	cardservice.connection.transmit(toBytes(f"a0 a4 00 00 02 7f 20"))
	cardservice.connection.transmit(toBytes(f"a0 a4 00 00 02 6f 20")) # select EF.KC
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 b0 00 00 09")) # Read 9 bytes from EF.KC
	print(f"[i] Current EF.Kc: {toHexString(data)}")
	
	# change Cipher key to 7
	cardservice.connection.transmit(toBytes(f"a0 d6 00 08 01 07")) # Change cipher key to 7 i.e not set
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 b0 00 00 09"))  # Read 9 bytes from EF.KC
	print(f"[i] Changed EF.Kc: {toHexString(data)}")

	# change location status to not updated
	cardservice.connection.transmit(toBytes(f"a0 a4 00 00 02 6f 7e")) # select EF.LOCI

	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 b0 00 00 0b")) # Read 11 bytes from EF.LOCI
	print(f"[i] Current EF.LOCI: {toHexString(data)}")

	cardservice.connection.transmit(toBytes(f"a0 d6 00 0a 01 01")) # Change update status to not updated
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 b0 00 00 0b"))  # Read 11 bytes from EF.LOCI
	print(f"[i] Changed EF.LOCI: {toHexString(data)}")


class PacketLogger:
	def __init__(self):
		self.stop_loop = False
		self.log_on = False
		self.log_file = ""
		self.log_files = []
		self.ftime = ""
		self.fsub = ""
		self.farfcn = ""
		self.cell_id = ""
		self.op_mcc = ""
		self.country = ""
		self.op_mnc = ""
		self.op_name = ""
		self.op_lac = ""

	def packet_parse(self, packet):
		layer_names = []
		for layers in packet.layers:
			layer_names.append(layers.layer_name)

		if 'gsmtap' not in layer_names:
			return

		if self.log_on:
			pchan = packet['gsmtap'].get_field('arfcn')
			ptime = packet['gsmtap'].get_field('ts')
			psub = packet['gsmtap'].get_field('sub_slot')

			if pchan == self.farfcn and ptime == self.ftime and psub == self.fsub and layer_names[-1] != 'lapdm':
				f = open(f"{self.log_file}_arfcn{self.farfcn}.txt", "a")
				if f"{self.log_file}_arfcn{self.farfcn}.txt" not in self.log_files:
					self.log_files.append(f"{self.log_file}_arfcn{self.farfcn}.txt")

				uplink = int(packet['gsmtap'].get_field('uplink'))

				dtap_type_name = ""
				for field_nm in packet[layer_names[-1]].field_names:
					if field_nm.startswith("msg_") and field_nm.endswith("_type"):
						dtap_type_name = field_nm
						break

				if len(dtap_type_name) != 0:
					f.write("(UL) ") if uplink else f.write("(DL) ")
					showname = packet[layer_names[-1]].get_field(dtap_type_name).showname_value.split("(")[0].strip()
					f.write(f"{showname}\n")


					if layer_names[-1] == 'gsm_a.dtap' and packet['gsm_a.dtap'].has_field('msg_mm_type'):
						dtap_type = int(packet['gsm_a.dtap'].get_field('gsm_a.dtap.msg_mm_type'), 16)

						#LUR
						if dtap_type == 0x08:
							f.write(f"\t{' '*3}Type: {packet['gsm_a.dtap'].get_field('gsm_a.dtap.updating_type').showname_value}\n")
							if packet['gsm_a.dtap'].has_field('3gpp_tmsi'):
								f.write(f"\t{' '*3}TMSI: 0x{int(packet['gsm_a.dtap'].get_field('3gpp.tmsi')):08x}\n")
							elif packet['gsm_a.dtap'].has_field('e212_imsi'):
								f.write(f"\t{' '*3}IMSI: {packet['gsm_a.dtap'].get_field('e212.imsi')}\n")

						#LUA
						if dtap_type == 0x02:
							if packet['gsm_a.dtap'].has_field('3gpp_tmsi'):
								f.write(f"\t{' '*3}TMSI: 0x{int(packet['gsm_a.dtap'].get_field('3gpp.tmsi')):08x}\n")

						#TMSI Reallocation
						if dtap_type == 0x1a:
							if packet['gsm_a.dtap'].has_field('3gpp_tmsi'):
								f.write(f"\t{' '*3}TMSI: 0x{int(packet['gsm_a.dtap'].get_field('3gpp.tmsi')):08x}\n")

						#LURj
						if dtap_type == 0x04:
							if packet['gsm_a.dtap'].has_field('rej_cause'):
								f.write(f"\t{' '*3}Cause: {packet['gsm_a.dtap'].get_field('rej_cause').showname_value}\n")

						#Id Resp
						if dtap_type == 0x19:
							if packet['gsm_a.dtap'].has_field('gsm_a_imeisv'):
								f.write(f"\t{' '*3}IMEI: {packet['gsm_a.dtap'].get_field('gsm_a.imeisv')}\n")
							elif packet['gsm_a.dtap'].has_field('e212_imsi'):
								f.write(f"\t{' '*3}IMSI: {packet['gsm_a.dtap'].get_field('e212.imsi')}\n")

						#Auth Req
						if dtap_type == 0x12:
							f.write(f"\t{' '*3}Cipher Key: {packet['gsm_a.dtap'].get_field('ciphering_key_sequence_number')}\n")
							f.write(f"\t{' '*3}RAND: 0x{packet['gsm_a.dtap'].get_field('rand').showname_value}\n")

						#Auth Resp
						if dtap_type == 0x14:
							f.write(f"\t{' '*3}SRES: 0x{packet['gsm_a.dtap'].get_field('sres').showname_value}\n")

						#MM Info
						if dtap_type == 0x32:
							if packet['gsm_a.dtap'].has_field('text_string'):
								f.write(f"\t{' '*3}Name: {packet['gsm_a.dtap'].get_field('text_string')}\n")
							if packet['gsm_a.dtap'].has_field('time_zone_time'):
								f.write(f"\t{' '*3}Time: {packet['gsm_a.dtap'].get_field('time_zone_time')}\n")

					elif layer_names[-1] == 'gsm_a.dtap' and packet['gsm_a.dtap'].has_field('msg_rr_type'):
						dtap_type = int(packet['gsm_a.dtap'].get_field('gsm_a.dtap.msg_rr_type'), 16)

						#CMC
						if dtap_type == 0x35:
							algo = int(packet['gsm_a.dtap'].get_field('gsm_a.rr.algorithm_identifier')) + 1
							f.write(f"\t{' '*3}Algorithm: A5/{algo}\n")

							if algo == 3 or algo == 4:
								# A5/3 unsupported so CMC frame not accepted by BTS
								# A5/4 definitely not supported
								self.stop_loop = True
								self.log_on = False

								# stop mobile
								command = "{ echo 'en'; echo 'off'; sleep 1; } | telnet localhost 4247"
								os.system(command)

				#Channel Release
				if layer_names[-1] == 'gsm_a.dtap' and packet['gsm_a.dtap'].has_field('msg_rr_type'):
					dtap_type = int(packet['gsm_a.dtap'].get_field('gsm_a.dtap.msg_rr_type'), 16)

					if dtap_type == 0x0d:
						if packet['gsm_a.dtap'].has_field('gsm_a_rr_rrcause'):
							f.write(f"\t{' '*3}Reason: {packet['gsm_a.dtap'].get_field('gsm_a.rr.RRcause').showname_value}\n")
						self.stop_loop = True
						self.log_on = False

						#stop mobile
						command = "{ echo 'en'; echo 'off'; sleep 1; } | telnet localhost 4247"
						os.system(command)

				f.close()

			else:
				if ptime == '0' and psub == '0':
					if packet[-1].layer_name == 'gsm_a.ccch' and packet['gsm_a.ccch'].has_field('gsm_a_dtap_msg_rr_type'):
						dtap_type = int(packet['gsm_a.ccch'].get_field('gsm_a.dtap.msg_rr_type'), 16)

						if dtap_type == 0x39:
							arfcn = packet['gsmtap'].get_field('arfcn')
							self.ftime = packet['gsm_a.ccch'].get_field('gsm_a.rr.timeslot')
							self.fsub = packet['gsm_a.ccch'].get_field('gsm_a.rr.tch_facch_sacchm')
							self.farfcn = packet['gsm_a.ccch'].get_field('gsm_a.rr.single_channel_arfcn')

							f = open(self.log_file + f"_arfcn{arfcn}.txt", "a")
							f.write(f"\nARFCN: {arfcn}\n")
							f.write(f"IA Ext: \n\tTimeslot: {self.ftime}, Subchannel: {self.fsub}, ARFCN: {self.farfcn}\n{'='*64}\n")
							f.close()

						elif int(packet['gsmtap'].get_field('chan_type'), 16) == 1:
							self.log_on = False


		else:
			if packet[-1].layer_name == 'gsm_a.ccch' and packet['gsm_a.ccch'].has_field('gsm_a_dtap_msg_rr_type'):
				dtap_type = int(packet['gsm_a.ccch'].get_field('gsm_a.dtap.msg_rr_type'), 16)

				#System Information 3 - cell info
				if dtap_type == 0x1b:
					self.cell_id = packet['gsm_a.ccch'].get_field('gsm_a.bssmap.cell_ci')
					self.op_mcc = packet['gsm_a.ccch'].get_field('e212.lai.mcc')
					self.country = packet['gsm_a.ccch'].get_field('e212.lai.mcc').showname_value.split('(')[0].strip()
					self.op_mnc = packet['gsm_a.ccch'].get_field('e212.lai.mnc').showname_value.split('(')[1].split(')')[0].strip()
					self.op_name = packet['gsm_a.ccch'].get_field('e212.lai.mnc').showname_value.split('(')[0].strip()
					self.op_lac = packet['gsm_a.ccch'].get_field('gsm_a.lac')

					print(f"Cell: {self.cell_id}, Location: {self.op_lac}, Operator: {self.op_mcc} ({self.country}) {self.op_mnc} ({self.op_name})")


				#Immediate Assignment
				if dtap_type == 0x3f:
					ia_mode = int(packet['gsm_a.ccch'].get_field('gsm_a.rr.dedicated_mode_or_tbf'), 16)

					if ia_mode == 0:
						self.log_on = True
						arfcn = packet['gsmtap'].get_field('arfcn')
						if packet['gsm_a.ccch'].has_field('gsm_a_rr_sdcch4_sdcchc4_cbch'):
							fmode = "SDCCH4"
						elif packet['gsm_a.ccch'].has_field('gsm_a_rr_tch_facch_sacchf'):
							fmode = "TCHF"
						else:
							fmode = "SDCCH8"
						self.ftime = packet['gsm_a.ccch'].get_field('gsm_a.rr.timeslot')
						self.fsub = packet['gsm_a.ccch'].get_field('gsm_a.rr.tch_facch_sacchm')
						self.farfcn = packet['gsm_a.ccch'].get_field('gsm_a.rr.single_channel_arfcn')

						f = open(self.log_file + f"_arfcn{arfcn}.txt", "a")
						f.write(f"\nARFCN: {arfcn}\n")
						f.write(
							f"\tCell ID: {self.cell_id}, LAC: {self.op_lac}, MCC: {self.op_mcc} ({self.country}), MNC: {self.op_mnc} ({self.op_name})\n")
						f.write(f"IA: \n\tMode: {fmode}, Timeslot: {self.ftime}, Subchannel: {self.fsub}, ARFCN: {self.farfcn}\n{'='*64}\n")
						f.close()

	

def pyshark_log():
	start_time = time.time()
	network_set = False
	
	try:
		capture = pyshark.LiveCapture(interface='lo', bpf_filter=f'udp and port 4729')

		for packet in capture.sniff_continuously():
			if time.time() - start_time > 40 and not network_set:
				network_set = True
				set_network()

			results_log.packet_parse(packet)

			if results_log.stop_loop:
				break
		
		capture.clear()
		capture.close()			
	except StopCapture:
		capture.clear()
		capture.close()
	except KeyboardInterrupt:
		capture.clear()
		capture.close()
	except Exception as e:
		print(f"[!] Error Message: {e}")



def start_phone(mobile_conf):
	results_log.stop_loop = False
	results_log.log_on = False
	
	sim_server = args.softsim + "/src/demo_server.rb"
	osmocom_mob = args.mobile if args.mobile else args.osmocombb + "/src/host/layer23/src/mobile/mobile"

	#close mobile if already running
	if len(prog_pids("mobile")[0]) != 0:
		os.kill(int(prog_pids("mobile")[0]), signal.SIGINT)
		time.sleep(5)

	if args.reset:
		reset_sim()

	#Start SIM server
	print(f"\t[?] Starting sim server")
	command = f"gnome-terminal -- /.'{sim_server}' -t pcsc -s unix -u /tmp/osmocom_sap"
	os.system(f"{command}")

	#Start omsocom phone
	print(f"\t[?] Starting Osmocom phone")
	command = f"gnome-terminal -- sudo /.'{osmocom_mob}' -c '{work_area}/config/{mobile_conf}'"
	os.system(f"{command}")


def set_network():
	# get subscriber info
	command = "{ echo 'enable'; echo 'show subscriber';  sleep 1; } | telnet localhost 4247"
	os.system(f"{command} > subscriber.txt")
	f = open("subscriber.txt", "r")
	subscriber_info = f.read()
	f.close()

	sub_imsi = subscriber_info.split("IMSI: ")[1].split("\n")[0]
	print(f"[+] Subscriber IMSI: {sub_imsi}")
	if "IMSI attached" not in subscriber_info:
		# scan for networks
		command = "{ echo 'enable'; echo 'network search 1';  sleep 1; } | telnet localhost 4247"
		os.system(command)

		while True:
			time.sleep(5)
			command = "{ echo 'enable'; echo 'network show 1';  sleep 1; } | telnet localhost 4247"
			os.system(f"{command} > scanned_networks.txt")
			f = open("scanned_networks.txt", "r")
			networks = f.read()
			f.close()

			if "Network " in networks:
				break

		if f"Network {sub_imsi[:3]}" in networks or f"Network mcc-mnc={sub_imsi[:3]}" in networks:
			print("[+] SIM card in home country")

			# connect to network
			if f"Network {sub_imsi[:3]}, {sub_imsi[3:6]}" in networks or f"Network mcc-mnc={sub_imsi[:3]}-{sub_imsi[3:6]}" in networks:
				command = f"{{ echo 'enable'; echo 'network select 1 {sub_imsi[:3]} {sub_imsi[3:6]}'; sleep 1; }} | telnet localhost 4247"
			elif f"Network {sub_imsi[:3]}, {sub_imsi[3:5]}" in networks or f"Network mcc-mnc={sub_imsi[:3]}-{sub_imsi[3:5]}" in networks:
				command = f"{{ echo 'enable'; echo 'network select 1 {sub_imsi[:3]} {sub_imsi[3:5]}'; sleep 1; }} | telnet localhost 4247"
			else:
				match = re.search(r"Network\s(\d+),\s(\d+)", networks)
				if not match:
					match = re.search(r"mcc-mnc=(\d+)-(\d+)", networks)

				command = f"{{ echo 'enable'; echo 'network select 1 {match.group(1)} {match.group(2)}'; sleep 1; }} | telnet localhost 4247"
			os.system(command)
		else:
			print("[+] SIM card roaming")
			match = re.search(r"Network\s(\d+),\s(\d+)", networks)
			if not match:
				match = re.search(r"mcc-mnc=(\d+)-(\d+)", networks)

			command = f"{{ echo 'enable'; echo 'network select 1 {match.group(1)} {match.group(2)}'; sleep 1; }} | telnet localhost 4247"
			os.system(command)


def analyse_files():
	os.system("clear")
	print(f"A5 algorithm analysis\n{'*' * 25}")
	cur_date = ""
	cur_imsi = ""
	cur_arfcn = ""
	imsi_pattern = r"IMSI:\s*(\d+)"
	arfcn_pattern = r"ARFCN:\s*(\d+)"
	mcc_pattern = r"MCC:\s*(\d+)"
	mnc_pattern = r"MNC:\s*(\d+)"
	lac_pattern = r"LAC:\s*(0x[0-9A-Fa-f]+)"
	cell_pattern = r"Cell ID:\s*(0x[0-9A-Fa-f]+)"
	sim_home = True

	for file in results_log.log_files:
		file_date = file.split("/")[-1].split("_")[0]
		file_time = file.split("/")[-1].split("_")[1]
		if file_date != cur_date:
			date_object = datetime.strptime(file_date, "%Y%m%d")
			print(f"\nDate: {date_object.strftime('%Y/%m/%d')}\n{'-' * 20}")
			cur_date = file_date
			cur_imsi = ""
			cur_arfcn = ""

		f = open(file, 'r')
		file_content = f.read()

		if "Location Updating Request" not in file_content:
			continue

		# Find imsi
		imsi = ""
		matches = re.findall(imsi_pattern, file_content)
		if len(matches) != 0:
			imsi = matches[0]
			if cur_imsi != imsi:
				print(f"\nTime: {datetime.strptime(file_time, '%H%M%S').strftime('%H:%M:%S')}")
				print(f"SIM used: {imsi}")
				matches = re.findall(mcc_pattern, file_content)
				if len(matches) != 0:
					if matches[0] != imsi[:3]:
						print(" [!] SIM roaming out of country")
						sim_home = False

				cur_imsi = imsi
				cur_arfcn = ""

		# check ARFCN
		matches = re.findall(arfcn_pattern, file_content)
		if len(matches) != 0:
			arfcn = matches[1]

			if cur_arfcn != arfcn:
				lac = re.findall(lac_pattern, file_content)[0] if len(
					re.findall(lac_pattern, file_content)) != 0 else "?"
				cell = re.findall(cell_pattern, file_content)[0] if len(
					re.findall(cell_pattern, file_content)) != 0 else "?"
				print(f" [-] Connected to ARFCN: {arfcn} (LAC: {lac}, Cell ID: {cell})")
				cur_arfcn = arfcn

				if sim_home and len(imsi) != 0:
					matches = re.findall(mnc_pattern, file_content)
					if len(matches) != 0:
						if imsi[3:5] == matches[0] or imsi[3:6] == matches[0]:
							print(" [+] SIM on home network")
						else:
							print(" [!] SIM roaming in country")

		if 'a5a' in file:
			pattern = r"A5/\d"
			pref_algo = re.findall(pattern, file_content)
			if len(pref_algo) != 0:
				print(f"   [+] Preferred algorithm: {pref_algo[0]}")
			else:
				print(f"   [+] Preferred algorithm: ?")
		else:
			algo_tested = f"A5/{file.split('_')[-2][-1]}"

			pattern = r"A5/\d"
			a5_allowed = re.findall(pattern, file_content)

			if "Ciphering Mode Command" in file_content:
				if "Location Updating Accept" in file:
					print(f"   [+] {algo_tested} accepted: Yes")
				elif len(a5_allowed) != 0 and a5_allowed[0] == algo_tested:
					print(f"   [+] {algo_tested} accepted: Yes")
				else:
					print(f"   [+] {algo_tested} accepted: No")
			elif "Location Updating Reject" in file_content and "Cause: Network failure" in file_content:
				print(f"   [+] {algo_tested} accepted: No")
			elif "Authentication Request" in file_content and "Ciphering Mode Command" not in file_content:
				print(f"   [+] {algo_tested} accepted: No")
			elif "Location Updating Accept" in file_content and "Ciphering Mode Command" not in file_content:
				print(f"   [+] {algo_tested} accepted: maybe - no auth performed")
			else:
				print(f"   [+] {algo_tested} accepted: ?")

		f.close()



def main():
	if args.input:
		if os.path.isdir(args.input):
			logs = os.listdir(args.input)
			logs.sort()
			for file in logs:
				if "arfcn" in file:
					results_log.log_files.append(args.input + file)
		elif os.path.isfile(args.input):
			results_log.log_files.append(args.input)
		else:
			sys.exit("[!] Not a valid log file or directory")

		analyse_files()
		sys.exit("\n[+] File analysis complete")
	else:
		if not args.softsim or not args.osmocombb:
			sys.exit("[!] Please specify the SoftSIM and osmocomBB installation location")


	osmocon_loc = args.osmocon if args.osmocon else args.osmocombb + "/src/host/osmocon/osmocon"
	osmocon_conf = args.firmware if args.firmware else args.osmocombb + "/src/target/firmware/board/compal_e88/layer1.highram.bin"


	# start osmocon
	if len(prog_pids("osmocon")[0]) != 0:
		running_cmds = process_cmd()

		if f"{osmocon_loc} -p {args.usbport} -m {args.model}" not in running_cmds:
			os.kill(int(prog_pids("osmocon")[0]), signal.SIGINT)
			os.system(f"gnome-terminal -- sudo /.'{osmocon_loc}' -p {args.usbport} -m {args.model} -c '{osmocon_conf}'")
	else:
		os.system(f"gnome-terminal -- sudo /.'{osmocon_loc}' -p {args.usbport} -m {args.model} -c '{osmocon_conf}'")	


	test_confs = ['a50mobile.cfg', 'a51mobile.cfg', 'a52mobile.cfg', 'a53mobile.cfg', 'a54mobile.cfg', 'a5amobile.cfg']

	for conf in test_confs:
		results_log.log_file = f"{work_area}/logs/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{conf[:3]}"
		print(f"[+] Testing network with {conf[:2].upper()}/{conf[2]}")
		start_phone(conf)
		pyshark_log()
		time.sleep(5)

	analyse_files()




if __name__ =="__main__":
	results_log = PacketLogger()
	main()


