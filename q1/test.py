import socket
from contextlib import closing

def check_socket(host, port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex((host, port)) == 0:
            print "Port is open "
            print port 
        #else:
            #print "Port is not open"
    pass

def main():
    host = '127.0.0.1'
    ports = [1,2]
    j = 200;
    while j < 600:
        ports.append(j)
        j += 1

    print ports

    for i in range (0, len(ports)):
		check_socket (host, ports[i])




if __name__ == '__main__':
    main()