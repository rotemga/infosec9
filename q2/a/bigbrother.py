from scapy.all import *


unpersons = set()


def spy(packet):
	if not packet.haslayer(TCP):
		return

	payload = str(packet[TCP].payload)
	if 'love' in payload:
		unpersons.add (packet[IP].src)
	pass


def main():
    sniff(prn=spy)


if __name__ == '__main__':
    main()
