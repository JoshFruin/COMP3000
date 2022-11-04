
import nmap

Scanner = nmap.PortScanner()

print("Network Scanner V1")

ip_add = input("Please enter the IP address which you want to scan: ")

ScanType = input ("""\n Please enter the type of scan you wish to run
                  1)SYN ACK Scan
                  2)UDP Scan
                  3)Comprehensive Scan \n""")
print("You have selected option: ", ScanType)

if ScanType == '1':
    print("Nmap Version: ", Scanner.nmap_version())
    Scanner.scan(ip_add, '1-1024', '-v -sS')
    print(Scanner.scaninfo())
    print("IP Status: ", Scanner[ip_add].state())
    print(Scanner[ip_add].all_protocols())
    print("Open Ports: ", Scanner[ip_add]['tcp'].keys())
elif ScanType =='2':
    print("Nmap Version: ", Scanner.nmap_version())
    Scanner.scan(ip_add, '1-1024', '-v -sU')
    print(Scanner.scaninfo())
    print("IP Status: ", Scanner[ip_add].state())
    print(Scanner[ip_add].all_protocols())
    print("Open Ports: ", Scanner[ip_add]['udp'].keys())
elif ScanType =='3':
    print("Nmap Version: ", Scanner.nmap_version())
    Scanner.scan(ip_add, '1-1024', '-v -sS -sV -sC -A -O')
    print(Scanner.scaninfo())
    print("IP Status: ", Scanner[ip_add].state())
    print(Scanner[ip_add].all_protocols())
    print("Open Ports: ", Scanner[ip_add]['tcp'].keys())
else:
    print("Please enter a valid option")
    