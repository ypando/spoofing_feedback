
### To compile: 

    gcc -g3 RawTCP_Lib/*.c include/*.h ./crackack_dns.c -o crackack_dns
    gcc -g3 RawTCP_Lib/*.c include/*.h ./crackack_email.c -o crackack_email

The two program only sends floods of ACK packets, if you want to spoof a TCP connection, you need to send SYN packets periodically.

Or, an attacker can use the SYN Cookie optimized TCP spoofing.
Run ```syn_flood.bash``` against a server first, then a connection can be established without sending a SYN packet.