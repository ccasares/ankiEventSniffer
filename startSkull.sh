#!/bin/bash

#device=`ls -1 /dev/ttyU* | head -3 | tail -1`
device='/dev/ttyUSB2'
#Skull
python /home/pi/ankiEventSniffer/sniffer.py -v --carToFollow=Skull $device
