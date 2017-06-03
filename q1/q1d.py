from scapy.all import *


def on_packet(packet):
	SYN = 0x02

	if (not packet.haslayer(TCP)) or (not packet.haslayer(IP)):
		return
	tcp = packet['TCP']
	ip = packet ['IP']

	if (ip.dst == '10.0.2.15'):
		return
	
	if (SYN & tcp.flags):
		SYN_ACK_PACKET = IP(dst=ip.src, src=ip.dst) / TCP(dport=tcp.sport,sport = tcp.dport, flags="SA") 
		send (SYN_ACK_PACKET)



def main():
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()
