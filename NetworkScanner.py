import sys
import nmap
import socket
import json
import pandas as pd
#from scapy.all import ARP, ETHER, srp
import mysql.connector

"""
from flask import Flask, render_template
app = Flask(__name__)

@app.route('/home/QuickScan')
def QuickScan():
    win32api.MessageBox(0, 'You have just run a python script on the page load!', 'Running a Python Script via Javascript', 0x00001000)
    
    return render_template('scan.html')
"""

Scanner = nmap.PortScanner()

ip_add = input("Please enter the IP address/IP Address Range you want to scan: ")

scanRange = Scanner.scan(hosts=(ip_add))

ScanType = input ("""\n Please enter the type of scan you wish to run
                  1)Quick Scan
                  2)Device Scan
                  3)OS Scan
                  4)Vuln Scan
                  5)Full Scan \n""")
print("You have selected option: ", ScanType)

if ScanType == '1': #QuickScan
    print("Nmap Version: ", Scanner.nmap_version())
    QuickscanData = Scanner.scan(scanRange, '1-1024', '-v -sS -O')
    """
    print(Scanner.scaninfo())
    print("IP Status: ", Scanner[ip_add].state())
    print(Scanner[ip_add].all_protocols())
    print("Open Ports: ", Scanner[ip_add]['tcp'].keys())
    """
    #print(QuickscanData)
    print(QuickscanData.csv())
    
    
elif ScanType =='2': #DeviceScan  
    print("Nmap Version: ", Scanner.nmap_version())
    DeviceScanData = Scanner.scan(ip_add, '1-1024', '-v -sU')
    print(Scanner.scaninfo())
    print("IP Status: ", Scanner[ip_add].state())
    print(Scanner[ip_add].all_protocols())
    print("Open Ports: ", Scanner[ip_add]['udp'].keys())
    print(DeviceScanData)
    
elif ScanType =='3': #OSScan 
    print("Nmap Version: ", Scanner.nmap_version())
    OSScanData = Scanner.scan(ip_add, '1-1024', '-O')
    """
    if 'osclass' in Scanner[ip_add]:
        for osclass in Scanner[ip_add]['osclass']:
         print('OsClass.type : {0}'.format(osclass['type']))
         print('OsClass.vendor : {0}'.format(osclass['vendor']))
         print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
         print('OsClass.osgen : {0}'.format(osclass['osgen']))
         print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
         print('')
    """
    print(OSScanData)
    
elif ScanType =='4': #VulnScan 
    print("Nmap Version: ", Scanner.nmap_version())
    VulnScanData = Scanner.scan(ip_add, '1-1024', '--script=vuln') #Doesn't Work yet but not a main problem -Nmap scripting engine
    print(Scanner.scaninfo())
    print("IP Status: ", Scanner[ip_add].state())
    print(Scanner[ip_add].all_protocols())
    print("Open Ports: ", Scanner[ip_add]['tcp'].keys())
    print(VulnScanData)

elif ScanType =='5': #FullScan
    print("Nmap Version: ", Scanner.nmap_version())
    FullScanData =Scanner.scan(ip_add, '1-65535', '-v -sS -sV -sC -A -O')
    print(Scanner.scaninfo())
    print("IP Status: ", Scanner[ip_add].state())
    print(Scanner[ip_add].all_protocols())
    print("Open Ports: ", Scanner[ip_add]['tcp'].keys())
    print(FullScanData)

else:
    print("Please enter a valid option")

#def GenerateQuickScanXML(QuickScanData):
    


"""
scannerdb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="C4bbages!",
  database="scannerdbmk2"
)

print(scannerdb) 


mycursor = scannerdb.cursor()

sql = "INSERT INTO quickscandata (deviceip, devicemac, devicename, osname, osversion) VALUES (%s, %s)"
val = ("John", "Highway 21")
mycursor.execute(sql, val)

scannerdb.commit()
"""