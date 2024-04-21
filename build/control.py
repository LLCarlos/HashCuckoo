#!/usr/bin/env python
"""
     HashCuckoo: Control program
"""

import argparse
import sys
import socket
import random
import struct
from flowManager       import Flow
from updateSwitches  import UpdateSwitches
from predictionModule import Prediction

from scapy.all import sniff, sendp
from scapy.all import Packet, IPOption
from scapy.all import Ether,IP, UDP, TCP, Raw, ICMP, Padding


import  thread, select, string

#Thresholds
TIME_OUT        = 5         #5s
THRESHOLD_TIME  = 10        #10s
THRESHOLD_SIZE  = 10000000  #10MB


TOL_TIME = #Define tolerance
TOL_SIZE = #Define tolerance


cTIME = #Current time
HOST_CONTROLLER = 'h9'  #Host controller communication

#TCP FLAGS:
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

list_ther = []

def handle_pkt(pkt, flow, pred, iface, ipController):
    print("Packet_In")
    tos = 0
    flagEnd = 0


    if(pkt[0][Ether].type == 0x800):
        tos = pkt[0][IP].tos
        if(pkt[0][IP].dst == ipController and (tos == 20 or tos == 32)):
            
            if(pkt[0][IP].proto == 0x11):
                if (Padding in pkt[0]):
                    pkt2 =Ether(pkt[0][Raw].load+pkt[0][Padding].load)
                else:
                    pkt2 =Ether(pkt[0][Raw].load)
                ipSrc  = pkt2[0][IP].src
                ipDst  = pkt2[0][IP].dst
                proto  = pkt2[0][IP].proto

                if(proto == 0x1): #ICMP
                    ident  = pkt2[0][ICMP].id
                    tupla = (ipSrc, ipDst, proto, ident)
                elif(proto == 0x11): #UDP
                    srcPort = pkt2[0][UDP].sport
                    dstPort = pkt2[0][UDP].dport
                    tupla = (ipSrc, ipDst, proto, srcPort, dstPort)
                elif(proto == 0x6): #TCP
                    srcPort = pkt2[0][TCP].sport
                    dstPort = pkt2[0][TCP].dport
                    tupla = (ipSrc, ipDst, proto, srcPort, dstPort)
                    
                    #FIN flag or timeOut:
                    F = pkt2[0][TCP].flags
                    print "flags...",F
                    if F & FIN:
                        flagEnd = 1


                if tos == 20: #New Flow
                    resul = flow.newFlow(ipSrc, ipDst, proto, tupla)

                    srcMac = pkt[0][Ether].src
                    pkt[0][Ether].src = pkt[0][Ether].dst
                    pkt[0][Ether].dst = srcMac

                    src= pkt[0][IP].src
                    pkt[0][IP].src = pkt[0][IP].dst
                    pkt[0][IP].dst = src
                    pkt[0][IP].tll = 64
                    pkt[0][IP].chksum = 0

                    sendp(pkt, iface=iface)

                    if resul:
                        resul = flow.upFlow(ipSrc, ipDst, proto, tupla)
                        print"...Successfully Processed!"
                   
                if flagEnd == 1:
                    print "END of FLOW!\n", tupla

                elif tos == 32: #Alert.
                    if(flow.getEF_List(tupla)):
                        print'\nEF already identified!'
                        
                    else:
                        flagPredictionEF = True
                        resul = flow.newFlow(ipSrc, ipDst, proto, tupla)
                        if resul: #Critical Flow Alert.
                            resul = flow.upFlow(ipSrc, ipDst, proto, tupla)
                            
                            srcMac = pkt[0][Ether].src
                            pkt[0][Ether].src = pkt[0][Ether].dst
                            pkt[0][Ether].dst = srcMac

                            src= pkt[0][IP].src
                            pkt[0][IP].src = pkt[0][IP].dst
                            pkt[0][IP].dst = src
                            pkt[0][IP].tll = 64
                            pkt[0][IP].chksum = 0
                            sendp(pkt, iface=iface)
                            print"...CRITICAL FLOW ALERT Successfully Processed!"

                            #LWR process
                            flagPredictionEF = pred.inferData(tupla, TOL_TIME, TOL_SIZE, cTIME):

                        if flagPredictionEF:
                            flow.insertEF(tupla)
                            print"\nNew EF IDENTIFICATED!\n", tupla
                        

    sys.stdout.flush()



def sniffing_start(iface, flow, pred, ipController):
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface = iface,
      prn = lambda x: handle_pkt(x, flow, pred, iface, ipController))
    print('end %s'%(iface))

    list_ther.remove(iface)


def main():
    
    hostController = HOST_CONTROLLER
    flow = Flow(hostController)
    switches     = flow.getSwitches()
    edge         = flow.getEdge()
    ipController = flow.getIpCpntroller()

    pred = Prediction(THRESHOLD_TIME, THRESHOLD_SIZE)
    print edge
    print ipController
    
    for h1,dic  in flow.routes.items():
        for h2, path in dic.items():
            print h1,h2, path
            print h1,h2, flow.routesEF[h1][h2],"\n"



    if switches is not None:
        print("SET_TABLES....")
        obj = UpdateSwitches(switches, edge.keys(), THRESHOLD_TIME, THRESHOLD_SIZE, TIME_OUT)
        obj.update()
        print("SET_TABLES....COMPLETED!")
    else:
        print("ERROR: SWITCHES IDENTIFICATION!") 

    try:
        threads_sniff = []
        for s, iface in edge.items():
            print 'Sniffing %s'%(iface)
            list_ther.append(iface)
            threads_sniff.append( thread.start_new_thread(sniffing_start, (iface, flow, pred, ipController)))

        while list_ther:
            pass
 
    except KeyboardInterrupt:
        print "\nEnd!"


if __name__ == '__main__':
    main()
