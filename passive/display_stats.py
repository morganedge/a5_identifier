#!/usr/bin/env python3

import os
from datetime import datetime, timedelta
import utils


def print_info(bdata):
	data_str = f"{bdata['MCC'] : ^4} |{bdata['MNC'] : ^4} |{bdata['LAC'] : <6} |{bdata['CID'] : <6} |{bdata['Freq'] : <7} "

	a5_total, a51_total, a52_total, a53_total, total_time = 0, 0, 0, 0, timedelta(seconds = 0)
	for entry in bdata["A5 count"]:
		scan_time = (datetime.strptime(entry['End Time'], '%Y/%m/%d %H:%M:%S') - datetime.strptime(entry['Start Time'], '%Y/%m/%d %H:%M:%S'))
		total_time += scan_time
		a5_total += entry["A5 count"]
		a51_total += entry["A5/1 count"]
		a52_total += entry["A5/2 count"]
		a53_total += entry["A5/3 count"]
		
	data_str += f"|{str(total_time) : ^10} |{a5_total : ^7} |{a51_total : ^6} |{a52_total : ^6} |{a53_total : ^6}"
	print(data_str)	


file_list = os.listdir("./scans/")
file_list.sort()
print("="*80)
print(f"{'MCC' : ^4} |{'MNC' : ^4} |{'LAC' : ^6} |{'CID' : ^6} |{'Freq' : ^7} |{'Scan Time' : ^10} |{'Total' : ^7} |{'Count' : ^18} ")
print(f"{' ' : ^4} |{' ' : ^4} |{' ' : ^6} |{' ' : ^6} |{' ' : ^7} |{' ' : ^10} |{'A5' : ^7} | {'A5/1' : ^6} {'A5/2' : ^6} {'A5/3' : ^6}")
print("="*80)

for file in file_list:
	if file.split(".")[-1] == "json":
		bts_data = utils.open_json(file)
		print_info(bts_data)


print("="*80)