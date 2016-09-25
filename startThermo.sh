#!/bin/bash

# USB
#device=`ls -1 /dev/ttyU* | head -1 | tail -1`
device='/dev/ttyUSB0'
#Thermo
python /home/pi/ankiEventSniffer/sniffer.py -v --carToFollow=Thermo $device
