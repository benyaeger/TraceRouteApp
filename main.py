import socket
from socket import *
from scapy.layers.inet import IP, TCP, sr1, ICMP, sr


def tracroute():
    print('Welcome To Traceroute By Ben Yaeger')
    print('*' * 50)

    host_valid = False
    while host_valid is not True:
        hostname = input('Please Enter Hostname To Trace (ex: google.com):')
        try:
            host_address = gethostbyname(hostname)
            print('Hostname "{}" was found at {}'.format(hostname, host_address))
            host_valid = True
        except:
            print('Failed to fetch hostname address')

    print('Initiating Traceroute Process')

    max_hops = 30
    timeout = 5

    packets = []
    for ttl in range(1, max_hops + 1):
        packet = IP(dst=host_address, ttl=ttl) / TCP(dport=80, flags='S')
        packets.append(packet)

    answered, unanswered = sr(packets, timeout=timeout, verbose=0)
    print('Packets Sent: {}, Answered Packets: {}, Unanswered Packets: {}'.format(len(answered) + len(unanswered), len(answered), len(unanswered)))
    ttl = 0
    for sent, reply in answered:
        ttl += 1
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
