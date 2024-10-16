import dpkt
from pcap_parallel import PCAPParallel #thank you Mr. Hardaker
import time
#import ipaddress --> will be used later for more performant IP reputation analysis


#TCP Flag vars
SYN_FLAG = 0x02
ACK_FLAG = 0x10
SYNACK_FLAG = 0x12
FIN_FLAG = 0x01
RST_FLAG = 0x04

def process_partial_pcap(file_handle):
    """
    Function: Counts the TCP flags in all IP packets in a packet capture
    Parameters: (pcap) packet capture file to process
    Returns: (dict) dictionary of the count of the flags found in TCP packets
    """
    syn_count = 0 #vars for counting packets
    ack_count = 0
    syn_ack_count = 0
    fin_count = 0
    rst_count = 0
    tcp_less = 0
    pcap = dpkt.pcap.Reader(file_handle)
    for timestamp, packet in pcap:
        eth = dpkt.ethernet.Ethernet(packet)
        #check if IP packet
        #you'll need to manually traverse each layer to verify in dpkt, scapy performs this automatically
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data

            #check if TCP present (dpkt equivalent of 'packet.haslayer(TCP)' from Scapy)
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                flags = tcp.flags
                if flags & SYNACK_FLAG == SYNACK_FLAG:
                    syn_ack_count += 1
                elif flags & SYN_FLAG:
                    syn_count += 1
                elif flags & ACK_FLAG:
                    ack_count += 1
                elif flags & FIN_FLAG:
                    fin_count += 1
                elif flags & RST_FLAG:
                    rst_count += 1
            else:
                tcp_less += 1
        else:
            tcp_less += 1

    return dict(SYNACKs=syn_ack_count, SYNs=syn_count, ACKs=ack_count, FINs=fin_count, RSTs=rst_count, NON=tcp_less)

if __name__ == "__main__":
    #this is more or less taken from @hardaker's usage section
    start = time.time()

    #PCAPParallel object --> callback is the function to run in parallel
    ps = PCAPParallel(
        f"resources/pcaps/synflood.pcap",
        callback=process_partial_pcap,
    )
    partial_results = ps.split() #splits the packet into segments to process
    
    #merging data
    total_counts = partial_results.pop(0).result()
    for partial in partial_results:
        next_counts = partial.result()
        for key in next_counts:
            total_counts[key] += next_counts[key]

    #printing results
    print('Packet results')
    for key,count in total_counts.items():
        print(f'{key:<8} count: {count}')
    print('%s seconds' % (time.time()-start))