from scapy.all import *
import binascii

msg = ""
need_to_stop = False

def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
	bits = ''.join(bits)
	return ''.join(chr(int(bits[i*8:i*8+8],2)) for i in range(len(bits)//8))



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


	

	msg +=  "{0:03b}".format(bits)

	if (seq  == ack-1):
		msg = text_from_bits(msg)
		need_to_stop = True
		return



def main():
    message = receive_message(1984)
    print('received: %s' % message)


if __name__ == '__main__':
    main()
