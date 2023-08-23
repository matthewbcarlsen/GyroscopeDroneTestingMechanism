#   Matthew Carlsen (UROP from Bethel University)
#   Drone Testing Apparatus
#   email: matthewcarlsen5@gmail.com 
#   7/19/2023

import serial.tools.list_ports
import keyboard
import csv
import time
import numpy as np
from datetime import datetime 
from zoneinfo import ZoneInfo
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from tinkerforge.ip_connection import IPConnection
from tinkerforge.bricklet_load_cell_v2 import BrickletLoadCellV2

ports = serial.tools.list_ports.comports()

HOST = "localhost" 
PORT = 4223
UID1 = "Zjr"
UID2 = "Khh"
UID3 = "VHs"
X_LOAD = []
Y_LOAD = []
Z_LOAD = []
i = 0
rowHeader = ['TimeStamp','Roll','Pitch','Yaw','LoadX','LoadY','LoadZ']
rowContent = [ ]

portList = []
for onePort in ports:
    portList.append(str(onePort))
    print(str(onePort))
 
for x in range(0,len(portList)):
    if "Arduino" in portList[x]:
        Arduino_COM = 'COM' + str(portList[x][3])

serialInst = serial.Serial()    
serialInst.baudrate = 9600
serialInst.port = Arduino_COM
serialInst.open() 

# US Pacific Time
us_eastern_dt = datetime.now(tz=ZoneInfo("America/New_York"))
current_second = str(datetime.now(tz=ZoneInfo("America/New_York")).second)
current_minute = str(datetime.now(tz=ZoneInfo("America/New_York")).minute)
current_hour = str(datetime.now(tz=ZoneInfo("America/New_York")).hour) 
current_day = str(datetime.now(tz=ZoneInfo("America/New_York")).day) 
current_month = str(datetime.now(tz=ZoneInfo("America/New_York")).month) 
filename = 'StopRotor_Test_' + current_month + '.' + current_day + '.' + current_hour + '.' + current_minute + '.' + current_second + '.csv'

with open(filename,'w') as csvfile:
    writer = csv.writer(csvfile)  
    writer.writerow(rowHeader)

    print('Entering Infinite Loop...') 
    if __name__ == "__main__": 
        ipcon = IPConnection() # Create IP connection
        lc1 = BrickletLoadCellV2(UID1, ipcon) # Create device object
        lc2 = BrickletLoadCellV2(UID2, ipcon)
        lc3 = BrickletLoadCellV2(UID3, ipcon)
        ipcon.connect(HOST, PORT) # Connect to brick

        while True:
            now = str(datetime.now(tz=ZoneInfo("America/New_York")))[18:26] 
            load1 = lc1.get_weight()
            load2 = lc2.get_weight()   
            load3 = lc3.get_weight()
            X_LOAD.append(load1)
            Y_LOAD.append(load2)
            Z_LOAD.append(load3) 

            if serialInst.in_waiting:
                packet = serialInst.readline()
                Roll_Pitch_Yaw = packet.decode('utf').rstrip('\n')
                RPY = Roll_Pitch_Yaw.split('  ')
                Roll = RPY[0]
                Pitch = RPY[1]
                Yaw = RPY[2]
                rowContent = [str(now),  str(Roll), str(Pitch), str(Yaw), str(load1), str(load2), str(load3)]
                print(rowContent)
                writer.writerow(rowContent)
                print("Roll: " + str(Roll) + ", Pitch: " + str(Pitch) + ", Yaw  : " + str(Yaw) + "Weight X: " + str(load1) + " g," + " Weight Y: " + str(load2) + " g," + " Weight Z: " + str(load3) + " g")  

            if keyboard.is_pressed("space"):
                print("space -key pressed to quit!")
                break   
 