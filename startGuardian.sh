#!/bin/bash

#device=`ls -1 /dev/ttyU* | head -2 | tail -1`
device='/dev/ttyUSB3'
#Guardian
python /home/pi/ankiEventSniffer/sniffer.py -v --carToFollow=Guardian $device

