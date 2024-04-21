#-*- coding: UTF-8 -*-
#Log analysis and results

import numpy as np
import matplotlib.pyplot as pl
import math
import pandas as df


TIME_OUT = 5
LIMITE_TIME = 10
LIMITE_SIZE = 10000000


#Start
if __name__ == '__main__':

    #frame.interface_id, frame.number frame.time_epoch
    #frame.len ip.src ip.dst ip.dsfield ip.proto icmp.ident
    #udp.srcport  udp.dstport   tcp.srcport   tcp.dstport


    ####Output files
    arqResul = open("resul.csv","w")
    arqResulEF = open("resulEF.csv","w")
    arqEF = open("metrics.csv","w")

    map_iface = {}
    data = {}
    dataEF = {}

    timeCONT = []
    sizeCONT = []
    pktECONT = []

    arq = open("map_ifaces.txt","r")
    aux  = arq.readlines()
    arq.close()
    ind = 0 
    for line in aux:
        k = line.split()[0]
        map_iface[int(ind)] = k
        ind = ind+1

    data = None
    outrosGET = 0
    data1 = df.read_csv("log_ifaces.csv", sep=",")

    data = data1.sort_values("frame.time_epoch")

    for p in data.groupby('ip.dsfield'):
        dscp = int(p[0],16)
        if dscp == 0:
            for  i in p[1].groupby('frame.interface_id'):
                if i[0] in map_iface.keys():
                    data[map_iface[i[0]]] = i[1]
        if dscp == 32:
            for  i in p[1].groupby('frame.interface_id'):
                if i[0] in map_iface.keys():
                    dataEF[map_iface[i[0]]] = i[1]

    arq = open("log_flow.csv","r")
    aux  = arq.readlines()
    arq.close()

    log_flow = {}
    log_flowEF = {}
    list_flows = []
    dic_flows   = {}

    for line in aux:
        line = line.split('\n')[0]
        tupla = line.split(',')
        n = len(tupla)
        k = tuple(tupla[:n-2])
        log_flow[k] = {'in': tupla[n-2], 'out': tupla[n-1]}
        list_flows.append(k)

    arq = open("log_flowEF.csv","r")
    aux  = arq.readlines()
    arq.close()

    for line in aux:
        line = line.split('\n')[0]
        tupla = line.split(',')
        n = len(tupla)
        k = tuple(tupla[:n-2])
        log_flowEF[k] = {'in': tupla[n-2], 'out': tupla[n-1]}

    
    #frame.interface_id, frame.number frame.time_epoch
    #frame.len ip.src ip.dst ip.dsfield ip.proto icmp.ident
    #udp.srcport  udp.dstport   tcp.srcport   tcp.dstport

    L_ICMP = ["ip.src","ip.dst","ip.proto","icmp.ident"]
    L_UDP  = ["ip.src","ip.dst","ip.proto","udp.srcport","udp.dstport"]
    L_TCP  = ["ip.src","ip.dst","ip.proto","tcp.srcport","tcp.dstport"]


    #for k, port in log_flow.items():
    for k in list_flows:
        if k in dic_flows.keys():
            dic_flows[k] = time + 1
            time = dic_flows[k]
        else:
            dic_flows[k] = 1
            time = 1

        in_face   = log_flow[k]["in"]
        out_face  = log_flow[k]["out"]

        if k[2] == '1':
            L_TUPLA = L_ICMP
        elif k[2] == '17':
            L_TUPLA = L_UDP
        elif k[2] == '6':
            L_TUPLA = L_TCP

        for i in data[in_face].groupby(L_TUPLA):
            tupla3 = []
            for j in i[0]:
                if isinstance(j, float):
                    j = int(j)
                tupla3.append( str(j))
            if(k ==tuple(tupla3)):
                d = i[1]
                timeEF = None
                in_FLow = ""
                out_FLow = ""
                out_EF = ""
                timeReation = ""
                sizeExed = ""
                indentiEF = ""
                sizeEEF = 0

                in_FLow = str(len(d))
                time = float(d[0:1]["frame.time_epoch"])
                timeL = float(d[0:1]["frame.time_epoch"])
                size  = 0
                flagEF = False
                contPktEF = None
                ind0 = 0
                contTime = 1
                contIN = 0
                for ind in range(0,len(d)):
                    
                    if(float(d[ind:ind+1]["frame.time_epoch"])- timeL) > TIME_OUT:
                        contTime = contTime +1
                        if contTime > time:
                            break
                        time = float(d[ind:ind+1]["frame.time_epoch"])
                        timeL = float(d[ind:ind+1]["frame.time_epoch"])
                        size  = 0
                        flagEF = False
                        contPktEF = None
                        ind0 = ind
                        contIN = 0
      
                    timeL = float(d[ind:ind+1]["frame.time_epoch"])
                    difTime = (timeL - time)
                    contIN =  contIN + 1
                    size  = size + int(d[ind: ind+1]["frame.len"])
                    if   difTime >  LIMITE_TIME and size > LIMITE_SIZE and flagEF is False:
                        contPktEF = ind - ind0
                        indentiEF  = str(ind-ind0)
                        timeEF = float(d[ind:ind+1]["frame.time_epoch"])
                        flagEF  = True

                in_FLow = str(contIN)

                #Output by default path.
                for saida in data[out_face].groupby(L_TUPLA):
                    tupla2 = []
                    for j in saida[0]:
                        if isinstance(j, float):
                            j = int(j)
                        tupla2.append( str(j))
                    if(k ==tuple(tupla2)):
                        d = saida[1]
                        contOutFlow = len(d)
                        contTime  = 1
                        contFlowout = 0
                        size2 = 0
                        contExce = 0
                        timeL = float(d[0:1]["frame.time_epoch"])
                        for ind4 in range(0,contOutFlow):
                            if(float(d[ind4:ind4+1]["frame.time_epoch"])- timeL) > TIME_OUT:
                                contTime = contTime +1
                                if contTime > time:
                                    break
                                contFlowout = 0 
                                size2 = 0
                                contExce = 0

                            if(contPktEF is not None and contFlowout >= contPktEF):
                                    size2  = size2 + int(d[ind4: ind4+1]["frame.len"])
                                    contExce = contExce + 1
                                

                            contFlowout = contFlowout +1
                            timeL = float(d[ind4:ind4+1]["frame.time_epoch"])

                        sizeEEF = size2
                        out_FLow = str(contFlowout)
                        sizeExed = str(size2)
                        pktExec  = str(contExce)
                        #print("Out_Flow, Num_Pkt: %d, pkt_Exec: %d, Bytes_Exedent: %d"%(contFlowout,contExce, size2))

                        break

                #Elephante Flow:
                if flagEF == True:
                    if k in log_flowEF.keys():
                        out_face = log_flowEF[k]["out"]

                        for saida in dataEF[out_face].groupby(L_TUPLA):
                            tupla2 = []
                            for j in saida[0]:
                                if isinstance(j, float):
                                    j = int(j)
                                tupla2.append( str(j))
                            if(k ==tuple(tupla2)):
                                d = saida[1]
                                contOutFlow = len(d)
                                timeL = None#float(d[0:1]["frame.time_epoch"])
                                for ind2 in range(0, contOutFlow):
                                    time2 = float(d[ind2:ind2+1]["frame.time_epoch"])
                                    if time2 > timeEF:
                                        timeR = time2 - timeEF
                                        timeReation = str(timeR)
                                        
                                        timeCONT.append(timeR)
                                        sizeCONT.append(size2)
                                        pktECONT.append(contExce)
                                        timeL = float(d[ind2:ind2+1]["frame.time_epoch"])
                                        contOUTEF = 0
                                        for ind5 in range(ind2, contOutFlow):
                                            if (float(d[ind5:ind5+1]["frame.time_epoch"])- timeL) > TIME_OUT:
                                                break
                                            else:
                                                contOUTEF = contOUTEF +1
                                        break

                                #print("ElephantFlow, Num_Pkt: %d, Reaction_Time: %f"%(contOutFlow,timeR))
                                out_EF = str(contOUTEF)
                                    
                                break

                resulOut = ""
                for t in k:
                    resulOut = resulOut + t+","
                resulOut = resulOut + "%s,%s,%s,%s,%s,%s,%s"%(in_FLow, indentiEF,out_FLow, out_EF,timeReation,sizeExed, pktExec) +"\n"
                print(resulOut)
                arqResul.write(resulOut)
                if flagEF is True:
                    arqEF.write("%s,%s,%s\n"%(timeReation,sizeExed, pktExec))
                    arqResulEF.write(resulOut)
                break

    arqResul.close()
    arqResulEF.close()

    timeReation = str(np.mean(timeCONT))
    sizeExed     = str(np.mean(sizeCONT))
    pktEEExed     = str(np.mean(pktECONT))
    print np.std(timeCONT)
    print("-------------------------------------\n"
        "\tMetrics Analysis (Avg)\n-------------------------------------\n"
        "Reaction Time (s):  %s\nExcess Bytes:     %s\n"
        "Excess Pkt Number: %s"%(timeReation,sizeExed,pktEEExed) )
    arqEF.write("%s,%s,%s\n"%(timeReation,sizeExed, pktEEExed))
    arqEF.close()
    print("-------------------------------------\n\nDone!")

    
