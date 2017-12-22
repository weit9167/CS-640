import sys
import os
import time
from switchyard.lib.userlib import *
from switchyard.lib.address import *
from time import *
from copy import deepcopy

class Router(object):

    def __init__(self, net):
        self.net = net
        self.my_interfaces = self.net.interfaces()

        # Setup forwarding table
        self.ftable = [];
        # First read from interfaces
        
        for intf in self.my_interfaces:
            print(intf)
            netaddr = IPv4Network(str('0.0.0.0')+'/'+str(intf.netmask))
            self.ftable.append([IPv4Address(int(intf.ipaddr) & int(intf.netmask)), intf.netmask, None , intf.name, netaddr.prefixlen])
            #print("{}, {}".format(intf.ethaddr, intf.name));
        # Then read from file
        
        f = open('forwarding_table.txt','r')
        for line in f:
            l = (line.rstrip('\n').split(' '))
            netaddr = IPv4Network(str('0.0.0.0')+'/'+l[1])
            l[0] = IPv4Address(l[0])
            l[1] = IPv4Address(l[1])
            l[2] = IPv4Address(l[2])
            
            l.append(netaddr.prefixlen)
            self.ftable.append(l)
        # Check ftable
        for ss in self.ftable:
            print(ss)

        # Setup IP_mac pair table
        self.IPmac_map = {}

        # Setup Queue for pkt
        self.pktQueue = []
        self.addrQueue = []
        self.bufferaddrQ = []
        self.bufferpktQ = []

        self.mymacs = [intf.ethaddr for intf in self.my_interfaces]
        self.myIP = [intf.ipaddr for intf in self.my_interfaces]

    def mk_icmperr(self,hwsrc, hwdst, ipsrc, ipdst, xtype, xcode=0, origpkt=None, ttl=64):
        ether = Ethernet()
        ether.src = EthAddr(hwsrc)
        ether.dst = EthAddr(hwdst)
        ether.ethertype = EtherType.IP
        ippkt = IPv4()
        ippkt.src = IPAddr(ipsrc)
        ippkt.dst = IPAddr(ipdst)
        ippkt.protocol = IPProtocol.ICMP
        ippkt.ttl = ttl
        ippkt.ipid = 0
        icmppkt = ICMP()
        icmppkt.icmptype = xtype
        icmppkt.icmpcode = xcode
        if origpkt is not None:
            xpkt = deepcopy(origpkt)
            #print(xpkt)
            i = xpkt.get_header_index(Ethernet)
            if i >= 0:
                del xpkt[i]
            #print(xpkt)
            icmppkt.icmpdata.data = xpkt.to_bytes()[:28]
            icmppkt.icmpdata.origdgramlen = len(xpkt)

        return ether + ippkt + icmppkt 

    def process_arp(self, arp, port):
        if arp :

            self.IPmac_map[arp.senderprotoaddr] = [arp.senderhwaddr, self.net.interface_by_name(port).ethaddr]
            #print(self.IPmac_map);         
            #print ("sender IP: {}, MAC: {}\n".format(str(arp.senderprotoaddr), str(arp.senderhwaddr)))
            #print ("target IP: {}, MAC: {}\n".format(str(arp.targetprotoaddr), str(arp.targethwaddr))) 

            # Check whether a request or reply
            if str(arp.targethwaddr) == 'ff:ff:ff:ff:ff:ff' :
                # This is an ARP request packet
                for i in range(len(self.myIP)):
                    if self.myIP[i] == arp.targetprotoaddr:
                        #print("Find interface\n")
                        # One interface has the same IP as the target IP in the pkt
                        # Send a ARP reply packet to the source interface
                        self.net.send_packet(port, create_ip_arp_reply(self.mymacs[i], arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr))
                        f = 1
                        break
            else :
                # Ths is an ARP reply packet
                ipaddr = arp.senderprotoaddr
                ethaddr = arp.senderhwaddr
                for i in range(len(self.addrQueue)):
                    if self.addrQueue[i][0] == ipaddr:
                        del self.addrQueue[i]
                        break
                #print(len(self.pktQueue))
                for i in reversed(range(len(self.pktQueue))):
                    #print(self.pktQueue[i][0])
                    if self.pktQueue[i][1] == ipaddr:
                        e = self.pktQueue[i][0].get_header(Ethernet)
                        e.dst = ethaddr
                        e.src = arp.targethwaddr
                        #print(self.pktQueue[i][0])
                        if str(self.pktQueue[i][0].get_header(IPv4).src) == '0.0.0.0':
                            self.pktQueue[i][0].get_header(IPv4).src = self.net.interface_by_name(self.pktQueue[i][2]).ipaddr
                            print("change src IP 1")
                        print(self.pktQueue[i][2])
                        self.net.send_packet(self.pktQueue[i][2], self.pktQueue[i][0])
                        del self.pktQueue[i]  


    def routing(self, ippkt):
        ipv4 = ippkt.get_header(IPv4)
        matchid = -1
        matchl = 0
        for i in range(len(self.ftable)):
            #print("Doing matching: {}, {}, {}".format(ipv4.dst, self.ftable[i][1],IPv4Address(int(ipv4.dst) & int(self.ftable[i][1]))), IPv4Address(self.ftable[i][0]))
            if (int(ipv4.dst) & int(self.ftable[i][1])) == int(self.ftable[i][0]) :
                # Find a match, check the prefix lentgh:
                #print("Find match: {}, {}, {}".format(ipv4.dst, self.ftable[i][1],IPv4Address(int(ipv4.dst) & int(self.ftable[i][1]))), IPv4Address(self.ftable[i][0]))

                if self.ftable[i][4] > matchl: 
                    # longer match
                    matchl = self.ftable[i][4]
                    matchid = i
        #print(self.ftable[matchid])                                 
        if matchid == -1:
            # TODO: add ICMP error 1 pkt sending
            print("ICMP Error 1")
            i = ippkt.get_header_index(Ethernet)
            del ippkt[i] # remove Ethernet header --- the errored packet contents sent with
                       # the ICMP error message should not have an Ethernet header
            icmp = ICMP()
            icmp.icmptype = ICMPType.DestinationUnreachable
            icmp.icmpcode = 0
            # ICMPCodeDestinationUnreachable.NetworkUnreachable = 0
            icmp.icmpdata.data = ippkt.to_bytes()[:28]
            ip = IPv4()
            ip.protocol = IPProtocol.ICMP
            ip.ttl = 64
            #ip.src =
            ip.dst = ipv4.src
            errpkt = Ethernet() + ip + icmp
            self.routing(errpkt)
            return 0         
        else :
            print("Start routing")
            ippkt.get_header(IPv4).ttl = ippkt.get_header(IPv4).ttl - 1
            if ippkt.get_header(IPv4).ttl == 0:
                # add ICMP error 2 pkt sending
                print("ICMP Error 2")

                i = ippkt.get_header_index(Ethernet)
                del ippkt[i] # remove Ethernet header --- the errored packet contents sent with
                           # the ICMP error message should not have an Ethernet header
                ippkt.get_header(IPv4).ttl = ippkt.get_header(IPv4).ttl + 1
                icmp = ICMP()
                
                icmp.icmptype = ICMPType.TimeExceeded
                icmp.icmpcode = 0
                # ICMPCodeTimeExceeded.TTLExpired: 0
                
                ip = IPv4()
                ip.protocol = IPProtocol.ICMP
                ip.ttl = 64
                #ip.src = ipv4.dst
                icmp.icmpdata.origdgramlen = len(ippkt)
                icmp.icmpdata.data = ippkt.to_bytes()[:28]
                ip.dst = ipv4.src
                errpkt = Ethernet() + ip + icmp
                print(errpkt.get_header(ICMP).icmpdata.data)

                
                self.routing(errpkt)
                return                
            # first lookup in ARP table
            nexthopIP = self.ftable[matchid][2]
            if not nexthopIP:
                nexthopIP = ipv4.dst
            #print("{}".format(ftable[matchid][2]))
            ethaddr = self.IPmac_map.get(nexthopIP)           
            if ethaddr != None :
                # Got the MAC address 
                print("Got IP in ARP table")                           
                e = ippkt.get_header(Ethernet)
                e.dst = ethaddr[0]
                e.src = ethaddr[1]
                if str(ippkt.get_header(IPv4).src) == '0.0.0.0':
                    print("change src IP 2")
                    ippkt.get_header(IPv4).src = self.net.interface_by_name(self.ftable[matchid][3]).ipaddr
                print(self.ftable[matchid][3])
                self.net.send_packet(self.ftable[matchid][3], ippkt)
                return
            # Then look in ARP queue
            #print("find IP in ARP queue") 
            f = 0
            for i in range(len(self.addrQueue)):
                if self.addrQueue[i][0] == nexthopIP:
                    f = 1
                    break
            if f == 0:
                for i in range(len(self.bufferaddrQ)):
                    if self.bufferaddrQ[i][0] == nexthopIP:
                        f = 1
                        break
            if f == 0:
                # Need to do ARP request, Try find longest same prefix 
                print("Need send an ARP pkt") 
                prelen = 0;
                intfid = -1;
                ip0 = int(nexthopIP)
                for i in range(len(self.my_interfaces)):
                    ip1 = int(self.my_interfaces[i].ipaddr)
                    currlen = ip0 & ip1;
                    if currlen > prelen:
                        prelen = currlen
                        intfid = i

                arp_pkt = create_ip_arp_request(self.my_interfaces[intfid].ethaddr, self.my_interfaces[intfid].ipaddr, nexthopIP )                               
                print("arp pkt sent:")
                print(arp_pkt)
                self.net.send_packet(self.my_interfaces[intfid].name, arp_pkt)

                #self.pktQueue.insert(0, [deepcopy(ippkt), nexthopIP, self.ftable[matchid][3]])
                #self.addrQueue.insert(0, [nexthopIP,time(),1, deepcopy(arp_pkt),self.my_interfaces[intfid].name])
                self.bufferpktQ.append([deepcopy(ippkt), nexthopIP, self.ftable[matchid][3]])
                self.bufferaddrQ.append([nexthopIP,time(),1, deepcopy(arp_pkt),self.my_interfaces[intfid].name])
                print("currtime = {} add to addrqueue".format(time()))
            else:
                print("Don't need send an ARP pkt, Already in ARP queue")
                self.bufferpktQ.append([deepcopy(ippkt), nexthopIP, self.ftable[matchid][3]])
                #self.pktQueue.insert(0, [deepcopy(ippkt), nexthopIP, self.ftable[matchid][3]])

    def load_buffer(self):
        for addr in self.bufferaddrQ:
            self.addrQueue.insert(0,addr)
        for pkt in self.bufferpktQ:
            self.pktQueue.insert(0,pkt)
        self.bufferaddrQ = []
        self.bufferpktQ = []        

    def refresh_addrqueue(self):
        #print("Check arpqueue ({}), pktqueue({})".format(len(self.addrQueue),len(self.pktQueue)))
        self.load_buffer()
        for entry in self.addrQueue:
            print("IP: {}, times: {}".format(entry[0],entry[2]))
        for i in reversed(range(len(self.addrQueue))):
            #print("IP is {}, ts {}, send time: {} currt {}".format(self.addrQueue[i][0], self.addrQueue[i][1],self.addrQueue[i][2],time()))
            if time() - self.addrQueue[i][1] > 1.0:
                #print("Need resend")
                if self.addrQueue[i][2] == 5:
                    # Already send 5 times, need to drop this addr and related pkts
                    for j in reversed(range(len(self.pktQueue))):
                        if self.pktQueue[j][1] == self.addrQueue[i][0]:
                            # ICMP error 3 pkt sending
                            ippkt = deepcopy(self.pktQueue[j][0])
                            print("ICMP Error 3 , pkt: {}".format(ippkt))

                            #print(ippkt)
                            ii = ippkt.get_header_index(Ethernet)
                            if ii >=0 :
                                del ippkt[ii] # remove Ethernet header --- the errored packet contents sent with
                                       # the ICMP error message should not have an Ethernet header
                            ippkt.get_header(IPv4).ttl = ippkt.get_header(IPv4).ttl + 1
                            icmp = ICMP()
                            icmp.icmptype = ICMPType.DestinationUnreachable
                            icmp.icmpcode = 1
                            # ICMPCodeDestinationUnreachable.HostUnreachable: 1
                            icmp.icmpdata.data = ippkt.to_bytes()[:28]
                            icmp.icmpdata.origdgramlen = len(ippkt)

                            ip = IPv4()
                            ip.protocol = IPProtocol.ICMP
                            ip.ttl = 64
                            #ip.src = self.net.interface_by_name(self.pktQueue[j][2]).ipaddr
                            ip.dst = ippkt.get_header(IPv4).src
                            errpkt = Ethernet() + ip + icmp
                            print("template icmperr: {}".format(errpkt))

                            self.routing(errpkt) 
                            del self.pktQueue[j]
                    del self.addrQueue[i]
                else:
                    self.addrQueue[i][2] += 1
                    self.addrQueue[i][1] = time()
                    print("Resend {} times {}".format(self.addrQueue[i][2],self.addrQueue[i][3]))
                    self.net.send_packet(self.addrQueue[i][4], self.addrQueue[i][3])
    
    def process_ipv4(self,ippkt):
        if ippkt.get_header(Arp):
            return
        ipv4 = ippkt.get_header(IPv4)
        #self.IPmac_map[ipv4.src] = ippkt[0].src
        if ipv4:
            if ipv4.dst in self.myIP:
                # This pkt is for interface itself, chech whether its a ICMP echo request pkt
                if ippkt.get_header(ICMP):
                    # This is a ICMP echo requests, send response
                    print("ICMP reply")
                    echo = ippkt.get_header(ICMP)
                    reply = ICMP()
                    reply.icmptype = ICMPType.EchoReply
                    reply.icmpdata.data = echo.icmpdata.data
                    reply.icmpdata.identifier = echo.icmpdata.identifier
                    reply.icmpdata.sequence = echo.icmpdata.sequence

                    ip = IPv4()
                    ip.dst = ipv4.src
                    ip.src = ipv4.dst
                    ip.ttl = 64
                    echopkt = Ethernet() + ip + reply
                    print(echopkt)
                    self.routing(echopkt)
                else:
                    print("ICMP Error 4")
                    # add ICMP error 4 pkt sending
                    i = ippkt.get_header_index(Ethernet)
                    del ippkt[i] # remove Ethernet header --- the errored packet contents sent with
                               # the ICMP error message should not have an Ethernet header
                    icmp = ICMP()
                    icmp.icmptype = ICMPType.DestinationUnreachable
                    icmp.icmpcode = 3
                    # ICMPCodeDestinationUnreachable.PortUnreachable: 3
                    icmp.icmpdata.data = ippkt.to_bytes()[:28]
                    ip = IPv4()
                    ip.protocol = IPProtocol.ICMP
                    ip.ttl = 64
                    ip.src = ipv4.dst
                    ip.dst = ipv4.src
                    errpkt = Ethernet() + ip + icmp
                    self.routing(errpkt)
            else:
                self.routing(ippkt)

    def check_arp_table(self):
        for myip, mymac in self.IPmac_map.items():
            for i in reversed(range(len(self.addrQueue))):
                if self.addrQueue[i][0] == myip: # found, can do the routing
                    del self.addrQueue[i]
                    break;
            for i in reversed(range(len(self.pktQueue))):
                    #print(self.pktQueue[i][0])
                    if self.pktQueue[i][1] == myip:
                        e = self.pktQueue[i][0].get_header(Ethernet)
                        e.dst = mymac[0]
                        e.src = mymac[1]
                        #print(self.pktQueue[i][0])
                        if str(self.pktQueue[i][0].get_header(IPv4).src) == '0.0.0.0':
                            self.pktQueue[i][0].get_header(IPv4).src = self.net.interface_by_name(self.pktQueue[i][2]).ipaddr
                            print("change src IP 1")
                        print(self.pktQueue[i][2])
                        self.net.send_packet(self.pktQueue[i][2], self.pktQueue[i][0])
                        del self.pktQueue[i] 


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''    
        print("Init finished.\n")
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))

                print("***Time = {}".format(time()))
                print(pkt)

                # Add the src IP/mac pair into ARP table
                

                # Treat the arp request/arp reply pkt
                self.load_buffer()
                self.process_arp(pkt.get_header(Arp), dev)

                # Treat the ip pkt
                self.process_ipv4(pkt)

                # before checking refresh, examine if the current ARP table can resolve
                # and ARP request in the queue
                self.check_arp_table()

                # Check addrQueue, if time > 1 resend
            self.refresh_addrqueue()
            








def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
