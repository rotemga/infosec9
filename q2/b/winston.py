from scapy.all import *
import binascii


def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def send_message(ip, port):
	msg = 'I love you'
	binary_msg = text_to_bits(msg)
	print int(binary_msg, 2)

	ack = len(binary_msg) / 3
	bits = ""
	seq = 0

	if (ack % 3) > 0:
		print (3 - len(binary_msg) % 3)
		binary_msg += '0'*(3 - len(binary_msg) % 3)
		ack += 1


	for i in range (0, ack):

		#if (len(binary_msg) < 3):
		#	padding = (3 - len(binary_msg))*'0'
		#	bits = padding + binary_msg
		#	print bits

				
		bits = binary_msg[0:3]
		binary_msg = binary_msg[3:]

		if ack==i:
			print bits


		packet = IP(dst=ip) / TCP(sport=65000, dport = port, flags="SA", ack = ack, seq = seq, reserved = int(bits,2))
		send(packet, count=1)
		seq += 1

	pass


def main():
    send_message('127.0.0.1', 1984)


if __name__ == '__main__':
    main()
