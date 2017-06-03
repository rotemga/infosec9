import socket
from contextlib import closing

def check_socket(host, port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((host, port)) == 0:
            print "Port is open"
        else:
            print "Port is not open"

def main():
	host = '127.0.0.1'
	ports = [20,21,22,23,24,25,26,27,28,29,80,90]
	for i in range (0, len(ports)):
		print ports[i]
		check_socket (host, ports[i])




if __name__ == '__main__':
    main()