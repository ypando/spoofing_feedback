
1. compile:
    
        sudo gcc -g3 ../RawTCP_Lib/*.c ../include/*.h -lpthread ./crackack_syn_cookie.c -o crackack_syn_cookie -lm


2. run ```fill_backlog.py``` to exactly fill the backlog queue, where the first connection is the target connection to spoof.

3. run ```sniff.py``` to track the change in responses to SYN probings.

4. run ```./crackack_syn_cookie 2>/dev/null``` to spoof a TCP connection as well as send SYN probes.

5. when sniff.py found successful spoofing attempt, the correct ack number will be provided
