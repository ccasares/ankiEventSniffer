#!/bin/bash

# Remove existing sniffer processes
pkill -f /dev/ttyUSB


cd /home/pi/ankiEventSniffer

while [ 1 -eq 1 ]
do
snifferDeviceCount=`ls -1 /dev/ttyU* 2>/dev/null | wc -l`
snifferProcessCount=`ps -ef | grep -v grep | grep  ttyUSB | wc -l`
#echo "Device Count: $snifferDeviceCount"
#echo "Process Count: $snifferProcessCount"
if [ $snifferDeviceCount -eq 0 ] && [ $snifferProcessCount -gt 0 ]; then
  #echo "Killing all existing sniffer processes"
  pkill -f /dev/ttyUSB
fi

if [ $snifferDeviceCount -gt 0 ]; then
  numberRunning=`ps -ef | grep \/home\/pi\/ankiEventSniffer\/sniffer.py | grep carToFollow=Thermo | wc -l`
  if [ $numberRunning -lt 1 ]; then 
    /home/pi/ankiEventSniffer/startThermo.sh > /home/pi/thermo.log&
  fi
fi

if [ $snifferDeviceCount -gt 1 ]; then
  numberRunning=`ps -ef | grep \/home\/pi\/ankiEventSniffer\/sniffer.py | grep carToFollow=Ground\ Shock | wc -l`
  if [ $numberRunning -lt 1 ]; then 
    /home/pi/ankiEventSniffer/startGroundShock.sh > /home/pi/groundShock.log &
  fi
fi

if [ $snifferDeviceCount -gt 2 ]; then
  numberRunning=`ps -ef | grep \/home\/pi\/ankiEventSniffer\/sniffer.py | grep carToFollow=Skull | wc -l`
  if [ $numberRunning -lt 1 ]; then 
    /home/pi/ankiEventSniffer/startSkull.sh > /home/pi/skull.log&
  fi
fi


if [ $snifferDeviceCount -gt 3 ]; then
  numberRunning=`ps -ef | grep \/home\/pi\/ankiEventSniffer\/sniffer.py | grep carToFollow=Guardian | wc -l`
  if [ $numberRunning -lt 1 ]; then 
    /home/pi/ankiEventSniffer/startGuardian.sh > /home/pi/guardian.log &
  fi
fi
sleep 3
done
