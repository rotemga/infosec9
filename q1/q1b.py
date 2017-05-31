from scapy.all import *


def on_packet(packet):
    pass # Reimplement me!


def is_blocked(ip):
    return False # Reimplement me!


def main():
    sniff(prn=on_packet)


if __name__ == '__main__':
    main()
