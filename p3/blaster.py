#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
#from switchyard.lib.common import *
from switchyard.lib.userlib import *
#from random import randint
import time


def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    f = open('blaster_params.txt', 'r').read().split(' ')
    blastee_ip = IPAddr(f[1])
    num_pkt = int(f[3])
    payload_len = int(f[5])
    sw = int(f[7])
    coarse_timeout = float(f[9])/1000.0
    recv_timeout = float(f[11])
    LHS = 1
    RHS = 0
    curr_pkt = 1
    my_window = {}
    
    re_send = []
    # stats
    start_time = time.time()
    num_reTX = 0
    num_coarse_TO = 0

    counts = []
    for i in range(num_pkt):
        counts.append(0)

    window_timer = time.time()  
    #print(time.time())
    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp, dev,pkt = net.recv_packet(timeout=recv_timeout/1000.0)
            recv_t = time.time()
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break
        '''
        print(my_window.keys())
        window_state=[]
        for p in my_window.keys():
            window_state.append(my_window[p][0])
        print(window_state)
        re_sendseq = []
        for p in re_send:
            seq_num = int.from_bytes(p[3].to_bytes()[:4], byteorder = 'big')
            re_sendseq.append(seq_num)
        print(re_sendseq)
        

        print("L: {} R: {}".format(LHS,RHS))
        window_state=[]
        for p in my_window.keys():
            window_state.append(my_window[p][0])
        print(window_state)
        '''
        if gotpkt:
            log_debug("I got a packet")

            # mark ACK in my_window list
            seq_num = int.from_bytes(pkt[3].to_bytes()[:4], byteorder = 'big')
            #print('receive pkt {} at {}'.format(seq_num,recv_t))
            if seq_num in my_window.keys():
                #print("ACK for pkt {} received".format(seq_num))
                my_window[seq_num][0] = 1
                while my_window[LHS][0] == 1:
                    my_window.pop(LHS)
                    LHS += 1
                    window_timer = time.time()
                    if LHS > RHS:
                        break
                if LHS > num_pkt:
                    break
            for i in reversed(range(len(re_send))):
                tofind = int.from_bytes(re_send[i][3].to_bytes()[:4], byteorder = 'big')
                if tofind == seq_num:
                    del re_send[i]



        else:
            log_debug("Didn't receive anything")
            

            '''
            Creating the headers for the packet
            '''
            if (len(re_send) == 0) and (RHS - LHS + 1 < sw) and curr_pkt <= num_pkt:
                my_pkt = Ethernet() + IPv4() + UDP()
                my_pkt[1].protocol = IPProtocol.UDP
                my_header1 = RawPacketContents((curr_pkt).to_bytes(4, byteorder = 'big') + (payload_len).to_bytes(2, byteorder = 'big'))
                my_pkt += my_header1
                my_header2 = RawPacketContents(bytes(payload_len))
                my_pkt += my_header2
                my_window[curr_pkt] = [0, my_pkt]
                #print(my_pkt)
                re_send.append(my_pkt)
                RHS += 1
                curr_pkt += 1

            if time.time() - window_timer > coarse_timeout:
                #print('timeout happens!!!!')
                num_coarse_TO += 1
                # do the re-transmission
                #re_send.append(re_send[0])
                window_timer = time.time()
                sorted_keys = list(my_window.keys())
                sorted_keys.sort()
                for seq in sorted_keys:
                    if my_window[seq][0] == 0:
                        re_send.append(my_window[seq][1])
                        my_window[seq][0] = 2



            '''
            Do other things here and send packet
            '''
            if len(re_send) > 0:
                snum = int.from_bytes(re_send[0][3].to_bytes()[:4], byteorder = 'big')
                #print('pkt {} send at {}'.format(snum, time.time()))
                net.send_packet(my_intf[0].name,re_send[0])
                my_window[snum][0] = 0
                num_reTX += 1
                counts[snum-1] += 1
                del re_send[0]
    end_time = time.time()
    print(counts)
    print('Total TX time (in seconds): {}'.format(end_time - start_time))
    print('Number of reTX: {}'.format(num_reTX - num_pkt))
    print('Number of coarse TOs: {}'.format(num_coarse_TO))
    print('Throughput(Bps): {}'.format((num_reTX * payload_len)/(end_time - start_time)))
    print('Goodput(Bps): {}'.format((num_pkt * payload_len)/(end_time - start_time)))
    net.shutdown()
