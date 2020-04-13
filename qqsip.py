#coding=utf-8
from scapy.all import *
import time

def packet_callback(packet):
    try:
        raw=packet[Raw]
        # print(hexdump(raw))
        aa=hexdump(raw,dump=True)
        # print(str(aa))
        if '02 00 48' in str(aa):
            print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            print("+++++++++++++++++++++++++++++++++++++++")
            print("[*] your_ip:%s"%packet[IP].src)
            print("[*] your_port:%s"%packet[UDP].sport)

            print("--------------------------------")
            print("[*] woof_ip:%s"%packet[IP].dst)

            print("[*] woof_port:%s"%packet[UDP].dport)
            print("+++++++++++++++++++++++++++++++++++++++")

    # print(packet.show())
        # return
    except Exception as e :
        pass
        # print(e)
    # print(packet.show())

# #开启嗅探
sniff(prn=packet_callback,store=0)
