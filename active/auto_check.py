#!/usr/bin/env python3

import sys
import os
import argparse
import subprocess
import shlex
import signal
import socket
import time
from datetime import datetime
import pyshark
from pyshark.capture.capture import StopCapture
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString, toBytes


parser = argparse.ArgumentParser(
	prog='A5 counter', 
	description='Counts the occurrence of the versions of A5 used in a network'
	)
parser.add_argument('-s', '--softsim', help="installation location of SoftSIM", required=True)
parser.add_argument('-o', '--osmocombb', help="installation location of OsmocomBB", required=True)
parser.add_argument('-O', '--osmocon', help="installation location of OsmocomBB osmocon", required=False)
parser.add_argument('-M', '--mobile', help="installation location of OsmocomBB mobile", required=False)
parser.add_argument('-F', '--firmware', help="installation location of firmware", required=False)
parser.add_argument('-m', '--model', help="osmocom-bb phone protocol", default="c123xor",
					choices=['c123', 'c123xor', 'c140', 'c140xor', 'c155', 'romload', 'mtk'], required=False)
parser.add_argument('-u', '--usbport', help="serial port connected to phone", default='/dev/ttyUSB0', required=False)
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


def reset_SIM():
	cardtype = AnyCardType()
	cardrequest = CardRequest(timeout=10, cardType=cardtype)
	cardservice = cardrequest.waitforcard()
	cardservice.connection.connect()

	# select EF.KC
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 a4 00 00 02 3f 00"))
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 a4 00 00 02 7f 20"))
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 a4 00 00 02 6f 20")) # select EF.KC
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 b0 00 00 09")) # Read 9 bytes from EF.KC
	print(f"[i] Current EF.Kc: {toHexString(data)}")
	
	# change Cipher key to 7
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 d6 00 08 01 07")) # Change cipher key to 7 i.e not set
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 b0 00 00 09"))  # Read 9 bytes from EF.KC
	print(f"[i] Changed EF.Kc: {toHexString(data)}")

	# change location status to not updated
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 a4 00 00 02 6f 7e")) # select EF.LOCI
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 b0 00 00 0b")) # Read 11 bytes from EF.LOCI
	print(f"[i] Current EF.LOCI: {toHexString(data)}")
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 d6 00 0a 01 01")) # Change update status to not updated
	data, sw1, sw2 = cardservice.connection.transmit(toBytes(f"a0 b0 00 00 0b"))  # Read 11 bytes from EF.LOCI
	print(f"[i] Changed EF.LOCI: {toHexString(data)}")


def logger(packet):
	global stop_loop
	global log_on
	global log_file
	global ftime
	global fsub
	global farfcn

	layer_names = []
	for layers in packet.layers:
		layer_names.append(layers.layer_name)

	if 'gsmtap' not in layer_names:
		return

	if log_on:
		pchan = packet['gsmtap'].get_field('arfcn')
		ptime = packet['gsmtap'].get_field('ts')
		psub = packet['gsmtap'].get_field('sub_slot')

		if pchan == farfcn and ptime == ftime and psub == fsub and layer_names[-1] != 'lapdm':
			f = open(log_file + f"_arfcn{farfcn}.txt", "a")

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
						f.write(f"\t{' '*3}Algorithm: A5/{int(packet['gsm_a.dtap'].get_field('gsm_a.rr.algorithm_identifier'))+1}\n")

			#Channel Release
			if layer_names[-1] == 'gsm_a.dtap' and packet['gsm_a.dtap'].has_field('msg_rr_type'):
				dtap_type = int(packet['gsm_a.dtap'].get_field('gsm_a.dtap.msg_rr_type'), 16)

				if dtap_type == 0x0d:
					#print(packet['gsm_a.dtap'].field_names)
					if packet['gsm_a.dtap'].has_field('gsm_a_rr_rrcause'):
						f.write(f"\t{' '*3}Reason: {packet['gsm_a.dtap'].get_field('gsm_a.rr.RRcause').showname_value}\n")
					stop_loop = True
					log_on = False

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
						ftime = packet['gsm_a.ccch'].get_field('gsm_a.rr.timeslot')
						fsub = packet['gsm_a.ccch'].get_field('gsm_a.rr.tch_facch_sacchm')
						farfcn = packet['gsm_a.ccch'].get_field('gsm_a.rr.single_channel_arfcn')

						f = open(log_file + f"_arfcn{arfcn}.txt", "a")
						f.write(f"\nARFCN: {arfcn}\n")
						f.write(f"IA Ext: \n\tTimeslot: {ftime}, Subchannel: {fsub}, ARFCN: {farfcn}\n{'='*64}\n")
						f.close()

					elif int(packet['gsmtap'].get_field('chan_type'), 16) == 1:
						log_on = False


	else: 
		if packet[-1].layer_name == 'gsm_a.ccch' and packet['gsm_a.ccch'].has_field('gsm_a_dtap_msg_rr_type'):
			dtap_type = int(packet['gsm_a.ccch'].get_field('gsm_a.dtap.msg_rr_type'), 16)

			#Immediate Assignment
			if dtap_type == 0x3f:
				ia_mode = int(packet['gsm_a.ccch'].get_field('gsm_a.rr.dedicated_mode_or_tbf'), 16)

				if ia_mode == 0:
					log_on = True
					arfcn = packet['gsmtap'].get_field('arfcn')
					if packet['gsm_a.ccch'].has_field('gsm_a_rr_sdcch4_sdcchc4_cbch'):
						fmode = "SDCCH4"
					elif packet['gsm_a.ccch'].has_field('gsm_a_rr_tch_facch_sacchf'):
						fmode = "TCHF"
					else:
						fmode = "SDCCH8"
					ftime = packet['gsm_a.ccch'].get_field('gsm_a.rr.timeslot')
					fsub = packet['gsm_a.ccch'].get_field('gsm_a.rr.tch_facch_sacchm')
					farfcn = packet['gsm_a.ccch'].get_field('gsm_a.rr.single_channel_arfcn')

					f = open(log_file + f"_arfcn{arfcn}.txt", "a")
					f.write(f"\nARFCN: {arfcn}\n")
					f.write(f"IA: \n\tMode: {fmode}, Timeslot: {ftime}, Subchannel: {fsub}, ARFCN: {farfcn}\n{'='*64}\n")
					f.close()

	

def pyshark_log():
	global stop_loop
	
	try:
		capture = pyshark.LiveCapture(interface='lo', bpf_filter=f'udp and port 4729')

		for packet in capture.sniff_continuously():
			logger(packet)

			if stop_loop:
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
	global stop_loop
	global log_on

	stop_loop = False
	log_on = False
	
	sim_server = args.softsim + "/src/demo_server.rb"
	osmocom_mob = args.mobile if args.mobile else args.osmocombb + "/src/host/layer23/src/mobile/mobile"

	#close mobile if already running
	if len(prog_pids("mobile")[0]) != 0:
		os.kill(int(prog_pids("mobile")[0]), signal.SIGINT)

	#reset_SIM()

	#Start SIM server
	print(f"\t[?] Starting sim server")
	command = f"gnome-terminal -- /.'{sim_server}' -t pcsc -s unix -u /tmp/osmocom_sap"
	os.system(f"{command}")

	#Start omsocom phone
	print(f"\t[?] Starting Osmocom phone")
	command = f"gnome-terminal -- sudo /.'{osmocom_mob}' -c '{work_area}/config/{mobile_conf}'"
	os.system(f"{command}")


def main():
	global log_file

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


	test_confs = ['a50mobile.cfg', 'a51mobile.cfg', 'a52mobile.cfg', 'a53mobile.cfg', 'a5amobile.cfg']

	for conf in test_confs:
		log_file = f"{work_area}/logs/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{conf[:3]}"
		print(f"[+] Testing network with {conf[:2].upper()}/{conf[2]}")
		start_phone(conf)
		pyshark_log()
		time.sleep(5)




if __name__ =="__main__":
	main()


