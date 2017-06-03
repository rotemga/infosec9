from scapy.all import *

unpersons = set()


def spy(packet):
	if not packet.haslayer(TCP):
		return

	payload = str(packet[TCP].payload)
	sender_ip = packet[IP].src
	
	distribution = [float(payload.count(c)) / len(payload) for c in set(payload)]
	entropy = -sum(p * math.log(p)/math.log(2.0) for p in distribution)

	if ('love' in payload) or (entropy > 3.0):
		print entropy
		unpersons.add (sender_ip)
		

	pass


def main():
    sniff(prn=spy)


if __name__ == '__main__':
    main()
