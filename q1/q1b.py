from scapy.all import *
import os


count_syn_dict = dict()
SYN = 0x02
timer = 0


def on_packet(packet):
	
	is_syn = 0

	#check if it SYN packet
	if (packet.hasLayer (TCP)):
		F = packet['TCP'].flags
		if (F & SYN): 
			is_syn = 1

	ip = packet[IP].src

	if (is_blocked(ip) and is_syn == 1):
		os.system ("iptables -A INPUT -s " + ip +" -j DROP")
		os.system ("iptables -A OUTPUT -d " + pi + " -j DROP")

	#add to dict
	add_to_dict( ip, is_syn)
	pass 


def is_blocked(ip):
	num_of_syn_in_last_minute = sum(count_syn_dict[ip])
	return (num_of_syn_in_last_minute > 15)


def add_to_dict(ip, syn):
	if not (ip in count_syn_dict):
		list = [0] * 60 #create list of size 60 with zeros.
		count_syn_dict[ip] = list
	count_syn_dict[ip][timer] = syn #update the list with the message
	update_timer ()





def update_timer ():
	timer = timer + 1
	timer = timer % 60 #mod to timer to be from 0 to 59.


def main():
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()
