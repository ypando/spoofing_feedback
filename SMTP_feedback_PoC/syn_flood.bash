# while true;do time hping3 -i u1 -s 2000 -c 3000 -S -q -p 25 -a 192.168.1.3 192.168.1.195;sleep 1;done
while true;do time hping3 -i u1 -s 2000 -c 101 -M 0 -S -q -p 25 -a 127.0.0.1 127.0.0.1;sleep 0.6;done
