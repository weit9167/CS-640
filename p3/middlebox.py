#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
#from switchyard.lib.common import *
from threading import *
#from random import randint
import time

import random

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    #for intf in my_intf:
    #    print(intf.ethaddr)
    myips = [intf.ipaddr for intf in my_intf]

    #myIP_MAC = {}
    #myIP_MAC[EthAddr('40:00:00:00:00:01')] = [IPAddr('192.168.100.2'), 30]
    #myIP_MAC[EthAddr('40:00:00:00:00:02')] = [IPAddr('192.168.200.2'), 30]
    # read the droping probability value from file
    f = open('middlebox_params.txt', 'r').read()
    prob = float((f.split(' '))[1])
    #print('the drop probability is {}'.format(prob))
    
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
            log_debug("I got a packet {}".format(pkt))
            #print(pkt)

        if dev == "middlebox-eth0":
        #if dev.ethaddr.toStr() == '40:00:00:00:00:01':
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            r = float(random.random())
            seq_num = int.from_bytes(pkt[3].to_bytes()[:4], byteorder = 'big')
            #print('random number is {}'.format(r))
            if r >= prob:
                e = pkt.get_header(Ethernet)
                e.src = net.interface_by_name("middlebox-eth1").ethaddr
                #e.src = EthAddr('40:00:00:00:00:02')
                #print('the packet {} is sent'.format(seq_num))
                net.send_packet("middlebox-eth1", pkt)
            else:
                print('pkt {} dropped.'.format(seq_num))

        elif dev == "middlebox-eth1":
        #elif dev.ethaddr.toStr == '40:00:00:00:00:02':
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            e = pkt.get_header(Ethernet)
            e.src = net.interface_by_name("middlebox-eth0").ethaddr
            #e.src = EthAddr('40:00:00:00:00:01')
            net.send_packet("middlebox-eth0", pkt)
        else:
            log_debug("Oops :))")

    net.shutdown()
