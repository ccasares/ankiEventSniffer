#!/bin/bash

# We can't assume tty devices are 0-3, so we just get the 1st-4th respectively...

deviceNumber=`expr ${1} + 1`
device=`ls -1 /dev/ttyU* | head -${deviceNumber} | tail -1`

if [ "${device}" == "" ]; then
 echo "No device found."
else
  sudo pkill -f $device
  echo "Device Reset"
fi
