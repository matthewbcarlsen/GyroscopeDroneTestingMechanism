#   Matthew Carlsen (UROP from Bethel University)
#   Drone Testing Apparatus Python Code to Convert Load Cell Data into Drone Reference Frame
#   email: matthewcarlsen5@gmail.com 
#   8/23/2023

import numpy as np
import csv 

##################### CHANGE FOR EACH RUN #####################
FILENAME = 'StopRotor_Test_8.23.16.36.43.csv'
###############################################################

def angleconversion(roll,pitch,yaw,loadx,loady,loadz):
        # https://en.wikipedia.org/wiki/Rotation_matrix
        # Tait-Bryan angles are alpha,beta,gamma about axes z,y,x, respectively.
        # alpha=yaw     beta=pitch      roll=gamma
    alpha = yaw
    beta = pitch 
    gamma = roll

    roll = np.deg2rad(roll)
    pitch = np.deg2rad(pitch)
    pitch = np.deg2rad(pitch)

    X_LOAD_CV = np.array([[loadx],[0],[0]])
    Y_LOAD_CV = np.array([[0],[loady],[0]])
    Z_LOAD_CV = np.array([[0],[0],[loadz]])

    A1 = np.cos(alpha)*np.cos(beta)
    A2 = np.cos(alpha)*np.sin(beta)*np.sin(gamma) - np.sin(alpha)*np.cos(gamma)
    A3 = np.cos(alpha)*np.sin(beta)*np.cos(gamma) + np.sin(alpha)*np.sin(gamma)
    B1 = np.sin(alpha)*np.cos(beta)
    B2 = np.sin(alpha)*np.sin(beta)*np.sin(gamma) + np.cos(alpha)*np.cos(gamma)
    B3 = np.sin(alpha)*np.sin(beta)*np.cos(gamma) - np.cos(alpha)*np.sin(gamma)
    C1 = -1*np.sin(beta)
    C2 = np.cos(beta)*np.sin(gamma)
    C3 = np.cos(beta)*np.cos(gamma)

    R1 = np.array([[1, 0, 0],[0, np.cos(roll), -1*np.sin(roll)],[0, np.sin(roll), np.cos(roll)]])
    R2 = np.array([[A1, A2, A3],[B1, B2, B3],[C1, C2, C3]])

    X_LOAD_DRONE = X_LOAD_CV
    Y_LOAD_DRONE = np.matmul(R1,Y_LOAD_CV)
    Z_LOAD_DRONE = np.matmul(R2,Z_LOAD_CV)

    XLOADTOT = np.add(X_LOAD_DRONE, Z_LOAD_DRONE)
    YLOADTOT = np.add(Y_LOAD_DRONE, Z_LOAD_DRONE)
    ZLOADTOT = np.add(Y_LOAD_DRONE, Z_LOAD_DRONE)
    
    XLOADTOT = XLOADTOT[0][0]
    YLOADTOT = YLOADTOT[1][0]
    ZLOADTOT = ZLOADTOT[2][0]
    
    F_TOT = [XLOADTOT,YLOADTOT,ZLOADTOT]
    return F_TOT

# https://realpython.com/python-csv/
oldrows = [];   updatedrows = []
with open('CSV_DATA/' + FILENAME, 'r') as csvfile:
    csv_reader = csv.reader(csvfile, delimiter = ',')
    next(csvfile)

    for row in csv_reader: 
        oldrows.append(row)
        ZYX = angleconversion(float(row[1]), float(row[2]), float(row[3]), float(row[4]), float(row[5]), float(row[6]))
        newrow = [row[1],row[2],row[3],ZYX[0],ZYX[1],ZYX[2]]
        updatedrows.append(newrow)

# print(oldrows)
# print('--------')
# print(updatedrows)
rowHeader = ['TimeStamp','Roll','Pitch','Yaw','LoadX','LoadY','LoadZ']
rowContent = [ ]

with open('CSV_DATA/UPDATED' + FILENAME, "w",newline='') as file:
    csvwriter = csv.writer(file)
    csvwriter.writerow(rowHeader)
    csvwriter.writerows(updatedrows)