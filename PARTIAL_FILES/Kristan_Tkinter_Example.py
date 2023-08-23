import numpy as np
import tkinter as tk   
import time  
import threading  

from tinkerforge.ip_connection import IPConnection
from tinkerforge.bricklet_load_cell_v2 import BrickletLoadCellV2

HOST = "localhost"
PORT = 4223 # Port of Tinkerforge communcations
UID1 = "Zjr" # relay output

ipcon = IPConnection() # Create IP connection
lc1 = BrickletLoadCellV2(UID1, ipcon)
ipcon.connect(HOST, PORT) # Connect to brickd

# Initialize variables
switch = True 
root = tk.Tk()
load = []

def run():
    while (switch == True): 
        #print('Data Point Collected') #Here is where insert my code 
        load.append(lc1.get_weight())
        time.sleep(0.1)
        if switch == False:  
            break   
    thread = threading.Thread(target=run)  
    thread.start()

def startbutton():
   print('Data collection initialized')
   global switch  
   switch = True

def stopbutton():
    print('Data collection has been stopped')
    global switch  
    switch = False

def kill():
    np.savetxt('loadcell.csv', load)
    root.destroy() 

onbutton = tk.Button(root, text = "Start Data Collection", command = run)    
onbutton.pack() 
offbutton =  tk.Button(root, text = "Stop Data Collection", command = stopbutton)    
offbutton.pack() 
killbutton = tk.Button(root, text = "Save Data and Exit Program", command = kill)    
killbutton.pack()  

root.mainloop() 
