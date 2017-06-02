from scapy.all import *


def stealth_syn_scan(ip, ports, timeout):
    result = []

    SYN = 0x02
    RST = 0x04
    ACK = 0x10
    #go over all ports, send syn to each port
    for i in range(0, len(ports)):
        #create syn packet
        SYN_PACKET = IP(dst=ip) / TCP(dport=ports[i], flags="S", seq=1000) 
        #send and recive one packet
        PACKET_RECIVED=sr1(SYN_PACKET, timeout=timeout)

        #check the flags
        if (PACKET_RECIVED):
            F = PACKET_RECIVED['TCP'].flags
            if (F & SYN) and (F & ACK):
                result.append('open')
            if (F & RST):
                result.append('closed')
        else:
            result.append('filtered')


    return result


def main(argv):
    if not 3 <= len(argv) <= 4:
        print('USAGE: %s <ip> <ports> [timeout]' % argv[0])
        return 1
    ip    = argv[1]
    ports = [int(port) for port in argv[2].split(',')]
    if len(argv) == 4:
        timeout = int(argv[3])
    else:
        timeout = 5
    results = stealth_syn_scan(ip, ports, timeout)
    for port, result in zip(ports, results):
        print('port %d is %s' % (port, result))


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
