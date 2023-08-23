#   Matthew Carlsen (UROP from Bethel University)
#   Drone Testing Apparatus
#   email: matthewcarlsen5@gmail.com 
#   7/19/2023


import serial.tools.list_ports
import csv
import time
import numpy as np
from datetime import datetime 
from zoneinfo import ZoneInfo
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import tkinter as tk  
from tkinter import *
from PIL import ImageTk, Image
from itertools import count
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from tinkerforge.ip_connection import IPConnection
from tinkerforge.bricklet_load_cell_v2 import BrickletLoadCellV2


ports = serial.tools.list_ports.comports()
HOST = "localhost" 
PORT = 4223
UID1 = "Zjr"; UID2 = "Khh"; UID3 = "VHs"

portList = []
for onePort in ports:
    portList.append(str(onePort))
    print(str(onePort))
 
for x in range(0,len(portList)):
    if "Arduino" in portList[x]:
        Arduino_COM = 'COM' + str(portList[x][3])

serialInst = serial.Serial();   serialInst.baudrate = 115200
serialInst.port = Arduino_COM;  serialInst.open() 

#Plot Information 
x_vals = [];    packet = [];    
X_LOAD = [];    Y_LOAD = [];    Z_LOAD = []
ROLL = [];      PITCH = [];     YAW = []
# load1 = 0;      load2 = 0;      load3 = 0
# Roll = 0;       Pitch = 0;      Yaw = 0
switch = False

def current_milli_time():
    return round(time.time()*1000)
start_time = current_milli_time()

def startbutton():
   global switch
   switch = True

def killbutton():
    plt.savefig('PLOTS.png')
    root.destroy()
    global switch 
    switch = False 

def stopbutton():
    global switch 
    switch = False

def plot_labels(x_axis, y_axis, title,ylim_min,ylim_max):
    font2 = {'family':'serif','color':'black','size':7}
    plt.xlabel(x_axis, font2)
    plt.ylabel(y_axis, font2)
    plt.title(title)
    plt.ylim(ylim_min, ylim_max)

# US Pacific Time
us_eastern_dt = datetime.now(tz=ZoneInfo("America/New_York"))
current_second = str(datetime.now(tz=ZoneInfo("America/New_York")).second)
current_minute = str(datetime.now(tz=ZoneInfo("America/New_York")).minute)
current_hour = str(datetime.now(tz=ZoneInfo("America/New_York")).hour) 
current_day = str(datetime.now(tz=ZoneInfo("America/New_York")).day) 
current_month = str(datetime.now(tz=ZoneInfo("America/New_York")).month) 
filename = 'StopRotor_Test_' + current_month + '.' + current_day + '.' + current_hour + '.' + current_minute + '.' + current_second + '.csv'

time.sleep(2) 
rowHeader = ['TimeStamp','Roll','Pitch','Yaw','LoadX','LoadY','LoadZ']
rowContent = [ ]
with open('CSV_DATA/'+ filename,'w') as csvfile:
    writer = csv.writer(csvfile)  
    writer.writerow(rowHeader)

    root = tk.Tk()
    root.geometry("900x800")
    root.configure(bg="grey")
    root.wm_title("Drone Testing GUI")
    label = tk.Label(root, text="Data for Drone Testing Apparatus",fg='white',bg='grey',font=("Courier",18,'bold')).pack(side = TOP)
    
    canvas = FigureCanvasTkAgg(plt.gcf(), master=root)
    canvas.get_tk_widget().pack(side = TOP)
    plt.gcf().subplots(2, 3)
    plt.gcf().subplots_adjust(left=.15,bottom = 0.1,right=.97,top=.93,wspace=.8,hspace=0.5)
   
    #Vertical Space
    spaceframe = Frame(root,bg='grey')
    spaceframe.pack(side = TOP,padx=(0, 3), pady=(3, 0)) 
    
    #Buttons
    buttonframe = Frame(root, bg='grey')
    buttonframe.pack(side = TOP)
    time_step = tk.Label(buttonframe, text='(YELLOW PLOT LINES = READING SENSORS BUT NOT COLLECTING DATA)',fg = 'white', bg = 'grey',font=("Courier",9,'bold')).pack(side = TOP)
    time_step = tk.Label(buttonframe, text='(RED PLOT LINES = DATA BEING COLLECTED)',fg = 'white', bg = 'grey',font=("Courier",9,'bold')).pack(side = TOP)
    onbutton = tk.Button(buttonframe, text = " Start Data Collection ",fg = 'white', bg = 'green', command = startbutton)    
    onbutton.pack(side = LEFT) 
    offbutton =  tk.Button(buttonframe, text = " Save Data & Exit Program ", fg = 'white', bg = 'firebrick1',command = killbutton)    
    offbutton.pack(side = LEFT)
    pausebutton = tk.Button(buttonframe, text = " Pause Data Collection ",fg = 'white', bg = 'deep sky blue', command = stopbutton)    
    pausebutton.pack(side = LEFT)
     
    #Vertical Space
    spaceframe2 = Frame(root, bg='grey')
    spaceframe2.pack(side = TOP,padx=(0, 10), pady=(10, 0)) 

    #############################################################          Text        #######################################################
    timelab = 'Time: ';                   xlab = 'X Load (grams): ';          ylab = 'Y Load (grams): ';          zlab = 'Z Load (grams): '
    rolllab = 'Roll Angle (deg): ';       pitchlab = 'Pitch Angle (deg): ';   yawlab = 'Yaw Angle (deg): '
    
    timeframe = Frame(root,bg='grey')
    timeframe.pack(side = TOP)
    time_txt = StringVar()
    TIME_txt = StringVar()
    timelabel = Label(timeframe,textvariable=time_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    TIMElabel = Label(timeframe,textvariable= TIME_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    timelabel.pack(side=LEFT)
    TIMElabel.pack(side=LEFT)

    loadxframe = Frame(root,bg='grey')
    loadxframe.pack(side = TOP)
    x_txt = StringVar()
    loadX_txt = StringVar()
    Xlabel = Label(loadxframe,textvariable = x_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    LoadXlabel = Label(loadxframe,textvariable = loadX_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    Xlabel.pack(side=LEFT)
    LoadXlabel.pack(side=LEFT)
   
    loadyframe = Frame(root,bg='grey')
    loadyframe.pack(side = TOP)
    y_txt = StringVar()
    loadY_txt = StringVar()
    Ylabel = Label(loadyframe,textvariable = y_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    LoadYlabel = Label(loadyframe,textvariable = loadY_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    Ylabel.pack(side=LEFT)
    LoadYlabel.pack(side=LEFT)

    loadzframe = Frame(root,bg='grey')
    loadzframe.pack(side = TOP)
    z_txt = StringVar()
    loadZ_txt = StringVar()
    Zlabel = Label(loadzframe,textvariable = z_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    LoadZlabel = Label(loadzframe,textvariable = loadZ_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    Zlabel.pack(side=LEFT)
    LoadZlabel.pack(side=LEFT)

    rollframe = Frame(root,bg='grey')
    rollframe.pack(side = TOP)
    roll_txt = StringVar()
    ROLL_txt = StringVar()
    rolllabel = Label(rollframe,textvariable = roll_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    ROLLlabel = Label(rollframe,textvariable = ROLL_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    rolllabel.pack(side=LEFT)
    ROLLlabel.pack(side=LEFT)

    pitchframe = Frame(root,bg='grey')
    pitchframe.pack(side = TOP)
    pitch_txt = StringVar()
    PITCH_txt = StringVar()
    pitchlabel = Label(pitchframe,textvariable = pitch_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    PITCHlabel = Label(pitchframe,textvariable = PITCH_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    pitchlabel.pack(side=LEFT)
    PITCHlabel.pack(side=LEFT)

    yawframe = Frame(root,bg='grey')
    yawframe.pack(side = TOP)
    yaw_txt = StringVar()
    YAW_txt = StringVar()
    yawlabel = Label(yawframe,textvariable=yaw_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    YAWlabel = Label(yawframe,textvariable= YAW_txt, fg='white', bg='grey', font=("Courier",12,'bold'))
    yawlabel.pack(side=LEFT)
    YAWlabel.pack(side=LEFT)


    def textoutput(now, Roll, Pitch, Yaw, load1, load2, load3):
        time_txt.set(timelab)
        TIME_txt.set(str(now))
        x_txt.set(xlab)
        loadX_txt.set(str(load1))
        y_txt.set(ylab)
        loadY_txt.set(str(load2))
        z_txt.set(zlab)
        loadZ_txt.set(str(load3))
        roll_txt.set(rolllab)
        ROLL_txt.set(str(Roll))
        pitch_txt.set(pitchlab)
        PITCH_txt.set(str(Pitch))
        yaw_txt.set(yawlab)
        YAW_txt.set(str(Yaw))

    ###########################################################################################################################################

    if __name__ == "__main__": 
        ipcon = IPConnection() # Create IP connection
        lc1 = BrickletLoadCellV2(UID1, ipcon) # Create device object
        lc2 = BrickletLoadCellV2(UID2, ipcon)
        lc3 = BrickletLoadCellV2(UID3, ipcon)
        ipcon.connect(HOST, PORT) # Connect to brick
        lc1.tare();     lc2.tare();     lc3.tare()

    def animate(i):
        global load1;   global load2;   global load3
        ax1, ax2,ax3,ax4,ax5,ax6 = plt.gcf().get_axes()
        ax1.set_title('Normal Title')
        now = str(datetime.now(tz=ZoneInfo("America/New_York")))[11:26]
        current_time = current_milli_time() - start_time
    
        serialInst.write(b'H') 
        packet.append(serialInst.readline().decode('utf').rstrip('\n'))
        Roll_Pitch_Yaw = packet[-1]
        RPY = Roll_Pitch_Yaw.split('  ')
        global Roll;    Roll = float(RPY[0])
        global Pitch;   Pitch = float(RPY[1])
        global Yaw;     Yaw = float(RPY[2]) 

        ROLL.append(Roll)
        PITCH.append(Pitch)
        YAW.append(Yaw)  
        ax4.cla();  ax5.cla();  ax6.cla()
        load1 = lc1.get_weight()
        load2 = lc2.get_weight()   
        load3 = lc3.get_weight()
        X_LOAD.append(load1)
        Y_LOAD.append(load2) 
        Z_LOAD.append(load3)
        ax1.cla();  ax2.cla();  ax3.cla()
        x_vals.append(float(current_time)/1000.0)

        if switch == True:
            plt.subplot(2,3,1)
            plot_labels("Time (s)", "Load (g)",'X',-2000,2000)
            ax1.plot(x_vals[-30:], X_LOAD[-30:],'-r')
            plt.subplot(2,3,2)
            plot_labels("Time (s)", "Load (g)",'Y',-2000,2000)
            ax2.plot(x_vals[-30:], Y_LOAD[-30:],'-r') 
            plt.subplot(2,3,3)
            plot_labels("Time (s)", "Load (g)",'Z',-2000,2000)
            ax3.plot(x_vals[-30:], Z_LOAD[-30:],'-r')
            plt.subplot(2,3,4)
            plot_labels("Time (s)", "Roll (deg)",'ROLL',-10,370)
            ax4.plot(x_vals[-30:], ROLL[-30:],'-r')
            plt.subplot(2,3,5)
            plot_labels("Time (s)", "Pitch (deg)",'PITCH',-10,370)
            ax5.plot(x_vals[-30:], PITCH[-30:],'-r')
            plt.subplot(2,3,6)
            plot_labels("Time (s)", "Yaw (deg)",'YAW',-10,370)
            ax6.plot(x_vals[-30:], YAW[-30:],'-r')
            rowContent = [str(now),  str(Roll), str(Pitch), str(Yaw), str(load1), str(load2), str(load3)]
            writer.writerow(rowContent)
            textoutput(now,  Roll, Pitch, Yaw, load1, load2, load3)
            
            # root.update()

        if switch == False: 
            plt.subplot(2,3,1)
            plot_labels("Time (s)", "Load (g)",'X',-2000,2000)
            ax1.plot(x_vals[-30:], X_LOAD[-30:],'-y')
            plt.subplot(2,3,2)
            plot_labels("Time (s)", "Load (g)",'Y',-2000,2000)
            ax2.plot(x_vals[-30:], Y_LOAD[-30:],'-y') 
            plt.subplot(2,3,3)
            plot_labels("Time (s)", "Load (g)",'Z',-2000,2000)
            ax3.plot(x_vals[-30:], Z_LOAD[-30:],'-y')
            plt.subplot(2,3,4)
            plot_labels("Time (s)", "Roll (deg)",'ROLL',-10,370)
            ax4.plot(x_vals[-30:], ROLL[-30:],'-y')
            plt.subplot(2,3,5)
            plot_labels("Time (s)", "Pitch (deg)",'PITCH',-10,370)
            ax5.plot(x_vals[-30:], PITCH[-30:],'-y')
            plt.subplot(2,3,6)
            plot_labels("Time (s)", "Yaw (deg)",'YAW',-10,370)
            ax6.plot(x_vals[-30:], YAW[-30:],'-y')


    ani = FuncAnimation(plt.gcf(), animate, interval=.0001, blit=False)
    tk.mainloop() 