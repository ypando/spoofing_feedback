iptables -F OUTPUT
iptables -A OUTPUT -p tcp --sport 12345 --tcp-flags RST RST -j DROP
iptables -A OUTPUT -p tcp --sport 13000 --tcp-flags RST RST -j DROP
iptables -A OUTPUT -p tcp --sport 13001 --tcp-flags RST RST -j DROP
