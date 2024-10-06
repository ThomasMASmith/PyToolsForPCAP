#imports 
from scapy.all import *
import time

#functions

def detect_synflood(capture):
    capture = rdpcap(capture)
    print('Number of packets:' + str(len(capture)))
    syn_count = 0
    ack_count = 0
    syn_ack_count = 0
    noTCP = 0
    for packet in capture:
        if packet.haslayer(TCP):
            if packet[TCP].flags == 'SA':
                syn_ack_count += 1
            if packet[TCP].flags == 'S':
                syn_count += 1
            if packet[TCP].flags == 'A':
                ack_count += 1
        else:
            noTCP += 1
    print(f'synack packets: {syn_ack_count}')
    print(f'syn packets: {syn_count}')
    print(f'ack packets: {ack_count}')
    print(f'packets without TCP {noTCP}')
#def detect_tcpreset(capture):

if __name__ == "__main__":
    start = time.time()
    capture = f'resources/pcaps/synflood.pcap'
    detect_synflood(capture)
    print('%s seconds' % (time.time()-start))

"""
NOTES



"""