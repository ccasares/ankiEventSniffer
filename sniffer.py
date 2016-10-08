__author__    = "ktown"
__copyright__ = "Copyright Adafruit Industries 2014 (adafruit.com)"
__license__   = "MIT"
__version__   = "0.1.0"

import os
import sys
import time
import datetime
import argparse
import json
import requests
import subprocess

import websocket
import thread

from SnifferAPI import Logger
from SnifferAPI import Sniffer
from SnifferAPI.Devices import Device
from SnifferAPI.Devices import DeviceList

# Variable to control lap
currentLap = 0

final_track_1 = 0x0e
final_track_2 = 0x0d
first_track_1 = 0x00
first_track_2 = 0x01

last_known_position = 0x00
new_known_position = 0x00
tentative_offtrack_position = 0x00

temp_current_lap = 0

race_status_file = "/home/pi/setup/race_status.dat"
race_count_file="/home/pi/setup/race_count.dat"
race_lap_file="/home/pi/setup/race_lap_%s.dat"
raceStatus = "UNKNOWN"
raceCount = 0
nodejs = "http://localhost:8888"
LAPURI = "/iot/send/data/urn:oracle:iot:device:data:anki:car:lap"
SPEEDURI = "/iot/send/data/urn:oracle:iot:device:data:anki:car:speed"
TRANSITIONURI = "/iot/send/data/urn:oracle:iot:device:data:anki:car:transition"
OFFTRACKURI = "/iot/send/alert/urn:oracle:iot:device:event:anki:car:offtrack"

mySniffer = None
"""@type: SnifferAPI.Sniffer.Sniffer"""

def get_race_status():
  try:
    with open(race_status_file, 'r') as f:
      first_line = f.readline()
      return(first_line)
  except (IOError):
      print "%s file not found!!!" % race_status_file
      return "UNKNOWN"

def get_race_count():
  try:
    with open(race_count_file, 'r') as f:
      first_line = f.readline()
      return(int(first_line))
  except (IOError):
      print "%s file not found!!!" % race_count_file
      return 0

def postRest(message, url):
    #print "posting %s" % message
    #print "url %s" % url
    data_json = json.dumps(message)
    #print "posting %s" % data_json
    headers = {'Content-type': 'application/json'}
#    print "[REST] %s  - %s - %s" % (myCarName,url, data_json)
    response = requests.post(url, data=data_json, headers=headers)
#    print "%s" % response
#    sys.stdout.flush()

def setup(serport, delay=6):
    """
    Tries to connect to and initialize the sniffer using the specific serial port
    @param serport: The name of the serial port to connect to ("COM14", "/dev/tty.usbmodem1412311", etc.)
    @type serport: str
    @param delay: Time to wait for the UART connection to be established (in seconds)
    @param delay: int
    """

    global mySniffer

    # Initialize the device on the specified serial port
    print "Connecting to sniffer on " + serport
    mySniffer = Sniffer.Sniffer(serport)
    # Start the sniffer
    print "Starting mySniffer..."
    mySniffer.start()
    # Wait a bit for the connection to initialise
    time.sleep(delay)

def getPiID():
    p1 = subprocess.Popen(["cat","/proc/cpuinfo"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p2 = subprocess.Popen(["grep","Serial"],stdin=p1.stdout,stdout=subprocess.PIPE)
    idLine = p2.stdout.read()
    p1.stdout.close()
    p2.stdout.close()
    splitVars = idLine.split(":")
    if(len(splitVars) == 2):
      id = splitVars[1].strip()
      print "Pi ID '%s'" % id
      return id
    print "Pi ID not found."
    return 0

def scanForDevices(scantime=3):
    """
    @param scantime: The time (in seconds) to scan for BLE devices in range
    @type scantime: float
    @return: A DeviceList of any devices found during the scanning process
    @rtype: DeviceList
    """
    if args.verbose:
        print "Starting BLE device scan ({0} seconds)".format(str(scantime))

    mySniffer.scan()
    time.sleep(scantime)
    devs = mySniffer.getDevices()
    return devs

def get_current_lap(car):
  global race_lap_file
  filename = race_lap_file % car
  try:
    with open(filename, 'r') as f:
      first_line = f.readline()
      return(int(first_line))
  except (IOError):
      print "%s file not found. Creating..." % filename
      with open(filename,"w+") as f:
        f.write("0")
      return 0

def set_lap(car, lap):
  global race_lap_file
  filename = race_lap_file % car
  try:
    with open(filename, 'r+') as f:
      f.seek(0)
      f.write("%s" % lap)
      f.truncate()
  except (IOError):
      print "%s file not found. Creating..." % filename
      with open(filename,"w+") as f:
        f.write("%s" % lap)

def inc_lap_count(car):
    l=int(get_current_lap(car))
    l=l+1
    set_lap(car, l)
#    return "%d" % l
    return l

def selectDevice(devlist):
    """
    Attempts to select a specific Device from the supplied DeviceList
    @param devlist: The full DeviceList that will be used to select a target Device from
    @type devlist: DeviceList
    @return: A Device object if a selection was made, otherwise None
    @rtype: Device
    """
    count = 0

    if len(devlist):
        print "Found {0} BLE devices:\n".format(str(len(devlist)))
        # Display a list of devices, sorting them by index number
        for d in devlist.asList():
            """@type : Device"""
            count += 1
            addressString = ":".join(['%02X' % a for a in d.address])
            print "Device: %s" % addressString
            print "  [{0}] {1} ({2}:{3}:{4}:{5}:{6}:{7}, RSSI = {8}) {9}".format(count, d.name,
                                                                             "%02X" % d.address[0],
                                                                             "%02X" % d.address[1],
                                                                             "%02X" % d.address[2],
                                                                             "%02X" % d.address[3],
                                                                             "%02X" % d.address[4],
                                                                             "%02X" % d.address[5],
                                                                             d.RSSI,
                                                                             d.carName)
        try:
            i = int(raw_input("\nSelect a device to sniff, or '0' to scan again\n> "))
        except KeyboardInterrupt:
            raise KeyboardInterupt
            return None
        except:
            return None

        # Select a device or scan again, depending on the input
        if (i > 0) and (i <= count):
            # Select the indicated device
            return devlist.find(i - 1)
        else:
            # This will start a new scan
            return None


def dumpPackets():
    global currentLap
    global trackSegment
    global totalTrackSegment
    global previousLapTime

    global final_track_1
    global final_track_2
    global first_track_1
    global first_track_2
    global last_known_position
    global new_known_position
    global temp_current_lap
    global tentative_offtrack_position

    global nodejs
    global LAPURI
    global SPEEDURI
    global TRANSITIONURI
    global OFFTRACKURI

    """Dumps incoming packets to the display"""

    wssend("FUERA DEL BUCLEEEEEE")

    # Get (pop) unprocessed BLE packets.
    packets =mySniffer.getPackets()
    #print "dumpPackets() called. Packets dumped: %d" % len(packets)
    # Display the packets on the screen in verbose mode
    if args.verbose:
        for packet in packets:
            if packet.blePacket is not None:
                # Display the raw BLE packet payload
                # Note: 'BlePacket' is nested inside the higher level 'Packet' wrapper class
                #print "here1"
                #print packet.payloadLength
                if packet.payloadLength != 19: # 19 is a common 'who knows what' packet.  Chuck it.
                  raceStatus = get_race_status()
                  raceCount = get_race_count()
                  currentLap = get_current_lap(myCarName)
                  dateTimeString=datetime.datetime.now().strftime("%y/%m/%d %H:%M:%S:%f")
                  packetlist = packet.blePacket.payload
                  #print packet.blePacket.payload
                  #print packet.eventCounter
                  #print packet.blePacket.payload
                  if len(packetlist) > 8:
                    raw = " ".join(['0x%02x' % b for b in packet.blePacket.payload])
                    wssend("%s - %s" % (dateTimeString, raw))
                    msgId = packet.blePacket.payload[8]
                    if msgId == 0x32: # U-Turn
                      #print "U-Turn 0x32"
                      wssend("U-Turn 0x32")
                      print " ".join(['0x%02x' % b for b in packet.blePacket.payload])
                    if msgId == 0x27:
                      if len(packet.blePacket.payload) > 16:
                        #print "%s - POSITION UPDATE" % dateTimeString
                        wssend("%s - POSITION UPDATE" % dateTimeString)
                        trackLocation = packet.blePacket.payload[9]
                        trackId = packet.blePacket.payload[10]
                        speed = packet.blePacket.payload[16]<<8 | packet.blePacket.payload[15]
                        speed = speed * 5

                        #print "loc: %d" % trackLocation
                        #print "id: %d" % trackId
                        #print "Speed: %d" % speed
                        dateTimeString=datetime.datetime.now().strftime("%y/%m/%d %H:%M:%S")

                        # Send to IoT Cloud
                        jsonData = {"deviceId":piId,"dateTime":int(time.time()),"dateTimeString":dateTimeString,"raceStatus": raceStatus,"raceId":raceCount,"carId":myDeviceAddress,"carName":myCarName,"speed":speed,"trackId":trackId,"lap":currentLap}
                        postRest(jsonData, "%s%s" % (nodejs,SPEEDURI) )

                        #print "Track ID: %d" % trackId
                        #sys.stdout.flush()

                        # FINISH LINE EVENT

                        if (trackId == 34):

                          wssend("%s - FILTER Finish Line Crossed" % dateTimeString)

                          # SET last_known_position to FINISH LINE to avoid the finish line missed check
                          last_known_position = 0x34
                          wssend("FILTER Setting last_known_position to = %s " % last_known_position)

                          timeNow = int(time.time()*1000)
                          if(previousLapTime == 0):
                            previousLapTime=timeNow
                          else:
                            lapTime = timeNow - previousLapTime

                            if(lapTime > 3000):

                              # Increase current lap
                              currentLap = inc_lap_count(myCarName)
                              temp_current_lap += 1
                              wssend("FILTER Finish Line: Increasing Lap count to %s" % temp_current_lap)

                              # Send to IoT Cloud
                              jsonData = {"deviceId":piId,"dateTime":int(time.time()),"dateTimeString":dateTimeString,"raceStatus": raceStatus,"raceId":raceCount,"carId":myDeviceAddress,"carName":myCarName,"lap":currentLap,"lapTime":lapTime}
                              postRest(jsonData, "%s%s" % (nodejs,LAPURI) )

                              wssend("%s: FILTER LapTime: %d" % (myCarName, lapTime))
                              trackSegment=0
                              wssend("FILTER Reset previous lap time.")
                              previousLapTime=timeNow
                            else:
                              #print "%s: Tracksegment: %d" % (myCarName, trackSegment)
                              #print "%s: LapTime: %d" % (myCarName, lapTime)
                              wssend("FILTER Lap too short... ignoring.")
                              #trackSegment=0


                            #print "Reset previous lap time."
                            #previousLapTime=timeNow

                    elif msgId == 0x29:
                      if len(packet.blePacket.payload) > 25:
                        # print "%s - TRANSITION UPDATE: " % dateTimeString
                        # wssend("%s - TRANSITION UPDATE: " % dateTimeString)

                        # VICTOR
                        # Get the new position
                        new_known_position = packet.blePacket.payload[9]
                        wssend("FILTER TRANSITION UPDATE TO POSITION: %s" % new_known_position)
                        wssend("FILTER COMMING FROM POSITION: %s" % last_known_position)
                        # Check if we are in the two first tracks.
                        if (new_known_position == first_track_1) or (new_known_position == first_track_2):
                            # CHECK IF WE LOSE THE FINISH LINE Event
                            if (new_known_position == first_track_2) and (last_known_position == first_track_1):
                                wssend("FILTER TRANSITION TO TRACK 1 to TRACK 2.... Ignoring")
                            elif (last_known_position == final_track_1) or (last_known_position == final_track_2):
                                # THERE WAS NOT FINISH LINE EVENT
                                wssend("%s - FILTER Finish Line Event Missed" % dateTimeString)

                                timeNow = int(time.time()*1000)
                                if(previousLapTime == 0):
                                  previousLapTime=timeNow
                                else:
                                  lapTime = timeNow - previousLapTime

                                # ADD CONTROL TO AVOID FAKE LAPS
                                if(lapTime > 3000):

                                  currentLap = inc_lap_count(myCarName)

                                  # Send to IoT Cloud
                                  jsonData = {"deviceId":piId,"dateTime":int(time.time()),"dateTimeString":dateTimeString,"raceStatus": raceStatus,"raceId":raceCount,"carId":myDeviceAddress,"carName":myCarName,"lap":currentLap,"lapTime":lapTime}
                                  postRest(jsonData, "%s%s" % (nodejs,LAPURI) )
                                  wssend("%s: FILTER LapTime: %d" % (myCarName, lapTime))
                                  trackSegment=0
                                  previousLapTime=timeNow

                                  temp_current_lap += 1
                                  wssend("FILTER Finish Line missed: Increasing Lap count to %s" % temp_current_lap)

                                else:
                                  wssend("FILTER Lap too short... ignoring.")
                            else:
                                wssend("FILTER FINISH LINE EVENT DETECTED.... ignoring.")
                                wssend("FILTER current track = %s " % new_known_position)
                                wssend("FILTER last track = %s " % last_known_position)

                        # UPDATE CAR POSITION
                        last_known_position = new_known_position
                        wssend("FILTER Setting last_known_position to = %s " % last_known_position)

                        #print " ".join(['0x%02x' % b for b in packetlist])
                        leftWheelDistance = packet.blePacket.payload[24]
                        rightWheelDistance = packet.blePacket.payload[25]

                        trackSegment=trackSegment+1
                        trackStyle=""
                        if leftWheelDistance == rightWheelDistance:
                          trackStyle="Straight"
                        elif leftWheelDistance == (rightWheelDistance+1):
                          trackStyle="Straight"
                        elif leftWheelDistance == (rightWheelDistance-1):
                          trackStyle="Straight"
                        elif leftWheelDistance == (rightWheelDistance+2):
                          trackStyle="Straight"
                        elif leftWheelDistance == (rightWheelDistance-2):
                          trackStyle="Straight"
                        elif leftWheelDistance > rightWheelDistance:
                          trackStyle="Right Turn"
                        elif leftWheelDistance < rightWheelDistance:
                          trackStyle="Left Turn"

                        timeNow = int(time.time()*1000)


                        #print "%s - Sending Transition %s: Left/Right 0x%02x: 0x%02x - %s - [%d]" % (dateTimeString, myCarName, leftWheelDistance, rightWheelDistance,trackStyle,trackSegment)
                        wssend("%s - Sending Transition %s: Left/Right 0x%02x: 0x%02x - %s - [%d]" % (dateTimeString, myCarName, leftWheelDistance, rightWheelDistance,trackStyle,trackSegment))
                        # Send to IoT
                        jsonData = {"deviceId":piId,"dateTime":int(time.time()),"dateTimeString":dateTimeString,"raceStatus": raceStatus,"raceId":raceCount,"carId":myDeviceAddress,"carName":myCarName,"trackStyle":trackStyle,"trackSegment":trackSegment,"lap":currentLap}
                        postRest(jsonData, "%s%s" % (nodejs,TRANSITIONURI) )

                    elif msgId == 0x2b: # ANKI_VEHICLE_MSG_V2C_VEHICLE_DELOCALIZED
                      #print "%s - Vehicle Delocalised" % dateTimeString
                      wssend("%s - FILTER Vehicle Delocalised" % dateTimeString)
                      wssend("FILTER Vehicle Delocalised: Last Known Possition = %s" % last_known_position)

                      # Calculate Wehicle Delocalised position
                      # Based in our test it should be last_known_position - 3 aprox.
                      tentative_offtrack_position = last_known_position - 3
                      wssend("FILTER Vehicle Delocalised: Sending drone to position = %s" % tentative_offtrack_position)

                      jsonData = {"deviceId":piId,"dateTime":int(time.time()),"dateTimeString":dateTimeString,"raceStatus": raceStatus,"raceId":raceCount,"carId":myDeviceAddress,"carName":myCarName,"lap":currentLap,"message":"Off Track", "lastKnownTrack":tentative_offtrack_position}
                      postRest(jsonData, "%s%s" % (nodejs,OFFTRACKURI) )
                    elif msgId == 0x1b: # ANKI_VEHICLE_MSG_V2C_BATTERY_LEVEL_RESPONSE
                      print " ".join(['0x%02x' % b for b in packetlist])
    else:
        print '.' * len(packets)
    return len(packets)

def on_message(ws, message):
	print message

def on_error(ws, error):
	print error

def on_close(ws):
	print "WS: ### closed ###"

def on_open(ws):
	print "WS: ### open ###"

def wssend(message):
        try:
              ws.send("%s - %s" % (myCarName, message))
        except Exception as e:
              pass

def start(ws):
        try:
              print "Trying to connect..."
              sys.stdout.flush()
	      ws.run_forever()
        except Exception as e:
              print "Error during setup WebSockets"
              sys.stdout.flush()

if __name__ == '__main__':
    """Main program execution point"""

    # Instantiate the command line argument parser
    argparser = argparse.ArgumentParser(description="Interacts with the Bluefruit LE Friend Sniffer firmware")

    # Add the individual arguments
    # Mandatory arguments:
    argparser.add_argument("serialport",
                           help="serial port location ('COM14', '/dev/tty.usbserial-DN009WNO', etc.)")
#    argparser.add_argument("deviceAddress",
#                           help="Device Hex Address (e.g. CC:1E:BE:1E:AC:C9:01)",default="XX")
    argparser.add_argument('--device', dest="deviceAddress", type=str, default="XX", help='Device Hex Address (e.g. CC:1E:BE:1E:AC:C9:01)')
    argparser.add_argument('--carToFollow', dest="carToFollow", type=str, default="XX", help='Car name e.g. Skull, Guardian')

    # Optional arguments:
    argparser.add_argument("-v", "--verbose",
                           dest="verbose",
                           action="store_true",
                           default=False,
                           help="verbose mode (all serial traffic is displayed)")

    # Parser the arguments passed in from the command-line
    args = argparser.parse_args()
    myDeviceAddress = args.deviceAddress
    myCarToFollow = args.carToFollow
    global trackSegment
    global totalTrackSegment
    global labNumber
    global ws
    trackSegment=0
    piId = getPiID()
    global previousLapTime
    previousLapTime=0
    try:
      txt = open("/home/pi/Desktop/totalTrackSegments")
      totalTrackSegments = txt.read()
      print "******  Track Segment Count: %s" % totalTrackSegments
    except IOError:
      print "******  No totalTrackSegments file found.  Not counting track segments."
      totalTrackSegments = -1

    # Display the libpcap logfile location
    # print "Logging data to " + os.path.join(Logger.logFilePath, "capture.pcap")

    # Try to open the serial port
    try:
        setup(args.serialport)

    except OSError:
        # pySerial returns an OSError if an invalid port is supplied
        print "Unable to open serial port '" + args.serialport + "'"
        sys.exit(-1)


    try:
        print "Opening WebSocket..."
        sys.stdout.flush()
        ws = websocket.WebSocketApp("ws://ws:8888/ws",
                on_message = on_message,
                on_open    = on_open,
                on_error   = on_error,
                on_close   = on_close)
        print "WebSocket object created..."
        sys.stdout.flush()
        thread.start_new_thread(start, (ws,))
    except Exception as e:
        print "Error during setup WebSockets"
        sys.stdout.flush()

    # Optionally display some information about the sniffer
    if args.verbose:
        print "Sniffer Firmware Version: " + str(mySniffer.swversion)

    # Scan for devices in range until the user makes a selection
    try:
        d = None
        """@type: Device"""
        print "Device We Want To Follow %s" % args.carToFollow
        while d is None:
            print "Scanning for BLE devices (5s) ..."
            devlist = scanForDevices()
            print "Length of Dev list: %d" % len(devlist)
            retryCount = 0
            while len(devlist) == 0 and retryCount < 3:
              retryCount = retryCount + 1
              print "Couldn't find devices... trying again."
              sys.stdout.flush()
              mySniffer.doExit()
              setup(args.serialport)
              devlist = scanForDevices()
            if retryCount == 3:
              mySniffer.doExit()
              exit()

            if args.carToFollow == "XX":
              if len(devlist):
                  # Select a device
                  d = selectDevice(devlist)
            else:
              print "Cars available:"
              for dl in devlist.asList():
                print "- %s" % dl.carName
                if dl.carName == args.carToFollow:
                  d = dl
#              for dl in devlist.asList():
#                addressString = ":".join(['%02X' % a for a in dl.address])
#                addressString = addressString[:-3]
#                print "Address String: %s" % addressString
#                print "Device Address: %s" % args.deviceAddress
#                if addressString == args.deviceAddress:
#                  d = dl

        # Start sniffing the selected device
        print "Attempting to follow device {0}:{1}:{2}:{3}:{4}:{5} - {6}".format("%02X" % d.address[0],
                                                                           "%02X" % d.address[1],
                                                                           "%02X" % d.address[2],
                                                                           "%02X" % d.address[3],
                                                                           "%02X" % d.address[4],
                                                                           "%02X" % d.address[5],
                                                                           "%s" % d.carName)
        print "Missed Packets: %d" % mySniffer.missedPackets
        #print "send: " + str(mySniffer.sendTestPacketToSniffer("test"))
        #x = mySniffer.getTestPacketFromSniffer
        #print "Type:"
        #type(x)
        #print "get: " + str(x)
        #from pprint import pprint
        #pprint(x)
        sys.stdout.flush()
        myCarName = d.carName
        myDeviceAddress = ":".join(['%02X' % a for a in d.address])
        # Make sure we actually followed the selected device (i.e. it's still available, etc.)
        if d is not None:
            response = mySniffer.follow(d)
            #print "Follow response: %02x" % response
            sys.stdout.flush()
        else:
            print "ERROR: Could not find the selected device"

        # Dump packets
        while True:
            packetCount = dumpPackets()
            #print "Packet count: "+str(packetCount)
            #sys.stdout.flush()
            time.sleep(1)

        # Close gracefully
        mySniffer.doExit()
        sys.exit()

    except KeyboardInterrupt:
        # Close gracefully on CTRL+C
        mySniffer.doExit()
        sys.exit(-1)
