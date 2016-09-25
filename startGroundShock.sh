#!/bin/bash

#device=`ls -1 /dev/ttyU* | head -4 | tail -1`
device='/dev/ttyUSB1'
#Ground Shock
python /home/pi/ankiEventSniffer/sniffer.py -v --carToFollow=Ground\ Shock $device
