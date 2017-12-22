'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    forwardTable = []
    capacity = 5

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        srcIndex = -1
        dstIndex = -1
        srcFlow = 0
        dstFlow = 0
        smallestIndex = 0

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            for i in range(0, len(forwardTable)):
                if forwardTable[i][0] == packet[0].src:
                    srcIndex = i
                    srcFlow = forwardTable[i][2]
                
            if (len(forwardTable) > 0):
                small = forwardTable[0][2]
            for j in range(1, len(forwardTable)):
                if forwardTable[j][2] < small:
                    small = forwardTable[j][2]
                    smallestIndex = j

            if srcIndex > -1:
                forwardTable[srcIndex] = [packet[0].src, input_port, srcFlow]
            else:
                if len(forwardTable) >= capacity:
                    forwardTable.pop(smallestIndex);
                    forwardTable.append([packet[0].src, input_port, 0])
                else:
                    forwardTable.append([packet[0].src, input_port, 0])  

            for i in range(0, len(forwardTable)):
                if forwardTable[i][0] == packet[0].dst:
                    dstIndex = i
                    dstFlow = forwardTable[i][2]

            if dstIndex > -1:
                forwardTable[dstIndex][2] = dstFlow+1
                net.send_packet(forwardTable[dstIndex][1], packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
