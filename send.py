#!/usr/bin/python

import os
import sys

# Harmonia MsgType 
WFIRST=1
WREST=2
READ=0
WRITECOMPLETION=3
HARMONIA_UDP_PORT=30000

if os.getuid() !=0:
    print("ERROR: This script requires root privileges. Use 'sudo' to run it.")
    quit()

from scapy.all import *

# define a harmonia header
class Harmonia(Packet):
    name="Harmonia"
    fields_desc = [
        ByteField("MsgType", 0),

        StrFixedLenField("none", b"", length=5),

        IntField("seq_index", 0),
        IntField("last_commit_seq", 0),
        IntField("obj_id", 0),
    ]


try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "192.168.101.8"

try:
    iface = sys.argv[2]
except:
    iface="veth0"

print ("Sending IP packet to", ip_dst)


def send_WFIRST_packet(obj_id):
    p = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
        IP(src="10.11.12.13", dst=ip_dst)/
        UDP(sport=HARMONIA_UDP_PORT,dport=HARMONIA_UDP_PORT)/
        Harmonia(MsgType=WFIRST, seq_index=0, obj_id=obj_id)/
        "WFIRST")
    
    sendp(p, iface=iface) 


def send_READ_packet(obj_id):
    p = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
        IP(src="10.11.12.13", dst=ip_dst)/
        UDP(sport=HARMONIA_UDP_PORT,dport=HARMONIA_UDP_PORT)/
        Harmonia(MsgType=READ, seq_index=0, obj_id=obj_id)/
        "READ")
    
    sendp(p, iface=iface) 

def send_WFIRST_packet(obj_id_):
    p = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
        IP(src="10.11.12.13", dst=ip_dst)/
        UDP(sport=HARMONIA_UDP_PORT,dport=HARMONIA_UDP_PORT)/
        Harmonia(MsgType=WFIRST, seq_index=0, obj_id=obj_id_)/
        "WFIRST")
    
    sendp(p, iface=iface) 


def send_WREST_packet(obj_id_):
    p = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
        IP(src="10.11.12.13", dst=ip_dst)/
        UDP(sport=HARMONIA_UDP_PORT,dport=HARMONIA_UDP_PORT)/
        Harmonia(MsgType=WREST, seq_index=0, obj_id=obj_id_)/
        "WREST")
    
    sendp(p, iface=iface) 

def send_WCOMPELETION_packet(obj_id_,seq_index_):
    p = (Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee")/
        IP(src="10.11.12.13", dst=ip_dst)/
        UDP(sport=HARMONIA_UDP_PORT,dport=HARMONIA_UDP_PORT)/
        Harmonia(MsgType=WRITECOMPLETION, seq_index=seq_index_, obj_id=obj_id_)/
        "WRITECOMPLETION")
    
    sendp(p, iface=iface) 

# send_WFIRST_packet(0x88)
    
send_READ_packet(0x88)
# send_READ_packet(0x89)
# send_WCOMPELETION_packet(0x88,4)
# send_WCOMPELETION_packet(0x88,5)
