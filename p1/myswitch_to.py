'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    forwardTable = {}
    
    while True:
        
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        for key in forwardTable.keys():
            if timestamp - forwardTable.get(key)[1] >= 10.0:
                forwardTable.pop(key)

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            if packet[0].src in forwardTable.keys():
                if forwardTable.get(packet[0].src)[0] == input_port:
                    forwardTable.get(packet[0].src)[1] = time.time()
                else:
                    forwardTable.get(packet[0].src)[0] = input_port
                    forwardTable.get(packet[0].src)[1] = time.time()
            else:
                forwardTable[packet[0].src] = [input_port, time.time()]

            if packet[0].dst in forwardTable.keys():
                if time.time() - forwardTable.get(packet[0].dst)[1] >= 10.0:
                    # pop and do boardcast
                    forwardTable.pop(packet[0].dst)
                    for intf in my_interfaces:
                        if input_port != intf.name:
                            log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                            net.send_packet(intf.name, packet)
                else:
                    net.send_packet(forwardTable.get(packet[0].dst)[0], packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)


            '''
            if packet[0].dst in forwardTable.keys(): 
                print ("packet that dest is known\n")
                net.send_packet(forwardTable[packet[0].dst], packet)
                if timestamp - forwardTable[packet[0].dst][1] >= 10.0:
                    forwardTable.pop(packet[0].dst)
                    for intf in my_interfaces:
                        if input_port != intf.name:
                            log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                            net.send_packet(intf.name, packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)


        forwardTable[packet[0].src]=[input_port, timestamp]
        '''
    net.shutdown()
