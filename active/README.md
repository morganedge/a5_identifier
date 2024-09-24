# Files used for active detection of A5 algorithms

## auto_check.py

```
usage: A5 counter [-h] -s SOFTSIM -o OSMOBB
                  [-m {c123,c123xor,c140,c140xor,c155,romload,mtk}]
                  [-u USBPORT]

Counts the occurrence of the versions of A5 used in a network

options:
  -h, --help            show this help message and exit
  -s SOFTSIM, --softsim SOFTSIM
                        installation location of SoftSIM
  -o OSMOBB, --osmobb OSMOBB
                        installation location of osmocom-bb
  -m {c123,c123xor,c140,c140xor,c155,romload,mtk}, --model {c123,c123xor,c140,c140xor,c155,romload,mtk}
                        phone protocol
  -u USBPORT, --usbport USBPORT
                        serial port connected to phone
```