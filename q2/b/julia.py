from scapy.all import *
import binascii

msg = ""
need_to_stop = False

def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
	n = int(bits, 2)
	return int2bytes(n).decode(encoding)

def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

def receive_message(port):

	while not (need_to_stop):
		sniff(count=1, prn=on_packet)
	return msg

def on_packet(packet):
	global msg, need_to_stop
	if (not(packet.haslayer(TCP)) or (packet['TCP'].sport != 65000)):
		return

	tcp = packet['TCP']
	ack = tcp.ack
	seq = tcp.seq
	bits = tcp.reserved

	print bits
	

	msg +=  "{0:03b}".format(bits)
	print seq
	print ack
	if (seq  == ack-1):
		msg = ''.join(msg)
		print msg

		msg = text_from_bits(msg)
		need_to_stop = True
		return



def main():
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
