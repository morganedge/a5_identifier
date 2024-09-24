# Files used for passive scanning of A5 algorithms

## a5_check.py

```
usage: A5 counter [-h] -f FREQ [-r RUNTIME]

Counts the occurrence of the versions of A5 used in a network

options:
  -h, --help            show this help message and exit
  -f FREQ, --freq FREQ  frequency of the BTS
  -r RUNTIME, --runtime RUNTIME
                        time in minutes to obtain sys info
```
e.g. python3 a5_check.py -f 952.8 
     python3 a5_check.py -f 952.8 -r 120

## display_stats.py

Reads the contents of the JSON files and display the data in a table

```
================================================================================
MCC  |MNC  | LAC   | CID   | Freq   |Scan Time  | Total  |      Count        
     |     |       |       |        |           |  A5    |  A5/1   A5/2   A5/3 
================================================================================
248  | 01  |5      |5087   |949.6   | 8:01:10   |  215   |  5    |  0    | 210  
248  | 01  |5      |5099   |952.8   | 17:20:01  | 2571   |  28   |  0    | 2543 
248  | 01  |5      |6682   |950.8   | 16:49:52  | 1936   | 200   |  0    | 1736 
248  | 02  |41     |50141  |925.6   | 8:00:00   |  46    |  46   |  0    |  0   
248  | 02  |41     |50967  |926.4   | 8:00:00   |  180   | 180   |  0    |  0   
248  | 02  |41     |52181  |934.4   | 17:10:01  |  290   | 290   |  0    |  0   
248  | 02  |41     |52183  |934.0   | 16:30:00  |  395   | 395   |  0    |  0   
248  | 03  |1171   |36748  |937.8   | 16:00:01  |  241   | 241   |  0    |  0   
248  | 03  |1171   |4154   |944.4   | 20:20:02  |  450   | 450   |  0    |  0   
248  | 03  |1171   |4156   |946.6   | 8:00:00   |  38    |  38   |  0    |  0   
================================================================================

```

