# a5_identifier

A selection of Python scripts to identify the A5 algorithms used by a GSM network or BTS.


## Prerequisites

Several apps and tools required

### Passive Method

1. gr-gsm: (https://github.com/ptrkrysik/gr-gsm) 
2. SDR
	- Tested with HackRF and RTL-SDR

### Active Method

1. osmocom-bb: (https://github.com/osmocom/osmocom-bb) 
	- Installation: https://osmocom.org/projects/baseband/wiki/Software_Getting_Started
2. SoftSIM: (https://github.com/osmocom/softsim)
	- Installation: (https://osmocom.org/projects/baseband/wiki/SoftSIM)
3. osmcom-bb phone: (https://osmocom.org/projects/baseband/wiki/Phones)
4. card reader
5. SIM cards


## Installation

sudo apt install gnome-terminal  
python3 -m pip install -r requirements.txt