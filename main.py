import socket
from socket import *
from scapy.layers.inet import IP, TCP, sr1, ICMP


def tracroute():
    print('Welcome To Traceroute By Ben Yaeger')
    print('*' * 50)

    host_valid = False
    while host_valid is not True:
        hostname = input('Please Enter Hostname To Trace (ex: google.com):')
        try:
            host_address = gethostbyname(hostname)
            print('Hostname {} was found at {}'.format(hostname, host_address))
            host_valid = True
        except:
            print('Failed to fetch hostname address')

    print('Initiating Traceroute Process...')

    max_hops = 15
    timeout = 8

    for ttl in range(1, max_hops + 1):
        packet = IP(dst=host_address, ttl=ttl) / TCP(dport=80, flags='S')
        reply = sr1(packet, timeout=timeout, verbose=0)
        if reply is None:
            print(f'{ttl}\tRequest Timed Out')
        elif reply.haslayer(ICMP):
            print(f'{ttl}\t{reply.src}\tICMP\t{reply.getlayer(ICMP).proto}')
        elif reply.haslayer(TCP):
            tcp_layer = reply.getlayer(TCP)
            if tcp_layer.flags == 0x12:
                # SYN-ACK received
                print(f'{ttl}\t{reply.src}\tReached destination')
                break
            else:
                # Some other TCP response
                print(f'{ttl}\t{reply.src}\tReceived TCP response with flags: {tcp_layer.flags}')
        else:
            print(f'{ttl}\t{reply.src}\t{reply}')


if __name__ == '__main__':
    tracroute()
