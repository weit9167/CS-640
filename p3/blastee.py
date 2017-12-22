#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
#from switchyard.lib.common import *
from threading import *
import time

def switchy_main(net):
    my_interfaces = net.interfaces() # VERIFY: should only one, right???

    mymacs = [intf.ethaddr for intf in my_interfaces]

    fline = open('blastee_params.txt', 'r').read()
    args = fline.split(' ')
    myip = IPv4Address(args[1])
    num_pkts = args[3]

    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))

        # extract the sequence number
        seq_num = int.from_bytes(pkt[3].to_bytes()[:4], byteorder = 'big')
        #print('sequence number is: {}',format(seq_num))
        # construct an ACK packet
        # ether header
        e = pkt.get_header(Ethernet)
        e.dst = e.src
        e.src = mymacs[0]
        # ip header
        iphead = pkt.get_header(IPv4)
        iphead.dst = iphead.src
        iphead.src = myip
        # UDP header
        uhead = UDP()
        uhead.src = 4444
        uhead.dst = 5555
        new_pkt = Packet()
        # payload
        #print(pkt)
        if len(pkt[3].to_bytes()) >= 14:
            new_pkt = e + iphead + uhead + seq_num.to_bytes(4, byteorder = 'big') + pkt[3].to_bytes()[6:14]
        else:
            diff = 14 - len(pkt[3].to_bytes())
            new_pkt = e + iphead + uhead + seq_num.to_bytes(4, byteorder = 'big') + pkt[3].to_bytes()[6:]
            new_pkt.add_payload(bytes(diff))
        
        net.send_packet(my_interfaces[0].name, new_pkt)


    net.shutdown()
