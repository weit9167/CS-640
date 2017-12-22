'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import collections


def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    
    cache = collections.OrderedDict()
    capacity = 5

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            if packet[0].src in cache.keys():
                cache = collections.OrderedDict([(packet[0].src, input_port) if k == packet[0].src else (k, v) for k, v in cache.items()])
                #cache[packet[0].src] = input_port
            else:
                if len(cache) >= capacity:
                    cache.popitem(last = False)
                    cache[packet[0].src] = input_port
                else:
                    cache[packet[0].src] = input_port

            if packet[0].dst in cache.keys():
                value = cache.pop(packet[0].dst)
                cache[packet[0].dst] = value
                net.send_packet(value, packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
