import subprocess as sub
import shlex
command = shlex.split('sudo tcpdump -B 10000000 -n -S -i any src port 8000 and dst port 60020 and "tcp[tcpflags]&(tcp-syn|tcp-ack)==(tcp-syn|tcp-ack)"')


p = sub.Popen(command, stdout=sub.PIPE)

previous_seq = -1
previous_ack = -1
change_buffer = []
answer_buffer = []
for row in iter(p.stdout.readline, b''):

    row=str(row,'ascii')
    seq_and_ack_str = row.split('seq ')[1].split(', win')[0]
    seq,ack = seq_and_ack_str.split(', ack ')
    
    if ack==previous_ack and seq!=previous_seq:
        change_buffer.append(int(seq))
        answer_buffer.append(int(ack)) 
        # answer should be the first element -1 because server's SYN-ACK would add 1 to the seq number used in the probe SYN packets
    elif ack==previous_ack and seq==previous_seq:
        change_buffer=[]
        answer_buffer=[] 
        # syn cookie is still enabled

    if len(change_buffer)>50:
        print(answer_buffer)
        exit(0)

    previous_seq=seq  
    previous_ack=ack

# the script will go through ISN in the tcpdump output
# once it found continuous ISN changes, it would report successful spoofing attempt 
