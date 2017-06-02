from scapy.all import *
import os
import datetime


count_syn_dict = dict()
SYN = 0x02
timer = 0


def on_packet(packet):

	is_syn = 0
	now = datetime.datetime.now()

	if (not (packet.haslayer (TCP))):
		return
		
	#check if it SYN packet
	F = packet['TCP'].flags
	if (F & SYN): 
		is_syn = 1

	ip = packet[IP].src

	clean_time (ip, now)


	if (is_blocked(ip) and is_syn == 1):
		os.system ("iptables -A INPUT -s " + ip +" -j DROP")
		os.system ("iptables -A OUTPUT -d " + pi + " -j DROP")
		print ip

	#add to dict
	if (is_syn):
		add_to_dict( ip, now)
	pass 


def is_blocked(ip):
	if not (ip in count_syn_dict):
		return False
	
	return (len (count_syn_dict[ip]) > 15)


def add_to_dict(ip, now):
	if not (ip in count_syn_dict):
		list = [] #create empty list.
		count_syn_dict[ip] = list
	count_syn_dict[ip].append(now) #update the list with the message





def clean_time (ip, now):
	timeList = count_syn_dict[ip]
	for i in range (0, len(timeList)):
		delta = now - timeList[i]
		time_diff = divmod(delta.days * 86400 + delta.seconds, 60)
		if (time_diff[1] > 15):
			count_syn_dict[ip].remove(timeList[i])
	


def main():
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()
