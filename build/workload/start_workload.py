#Start workload using iperf
#Python2

import  thread, select, string
import subprocess
from datetime import datetime
import  time
import os
import numpy as np
import signal

M_PATH = '~/mininet/util/m'


list_thre = []

def nova_thread(line):

    tupla = line.split()
    client = tupla[0]
    serv = tupla[1]
    porta = tupla[2]
    timeD  = int(tupla[3])
    timeS  = int(tupla[4])

    time.sleep(timeS)
    print "Start Thread"
    ###SERVER
    command = str('%s %s iperf3 -s -p%s -1'%(M_PATH, serv,porta))
    arg = command.split()

    #pServ = subprocess.Popen(arg, stdin=subprocess.PIPE, stdout=subprocess.PIPE,  stderr=subprocess.PIPE)
    pServ = subprocess.Popen(arg)

    tii = 1.0 + np.random.rand()  #Random Start
    time.sleep(tii)
    
    ###CLIENT
    servIP = '10.0.%s.10'%(serv[1:])
    command = str('%s %s iperf3 -c %s -p%s -b10000000 -M1300 -t%d'%(M_PATH, client,servIP,porta,timeD))
    
    arg = command.split()
    
    # pClient = subprocess.Popen(arg, stdin=subprocess.PIPE, stdout=subprocess.PIPE,  stderr=subprocess.PIPE)
    pClient = subprocess.Popen(arg)

    out, error = pClient.communicate()
    print out

    #pClient.wait()
    #pClient.kill()
    #pServ.kill()
    if list_thre != None and line in list_thre:
    	list_thre.remove(line)



if __name__ == '__main__':

   
    try:
       
        print'Start Threads'
        pList = []
        arq3 = open("flows.txt", "r")
        dado = arq3.readlines()
        arq3.close()
        time.sleep(5)
        
        n = len(dado)
        for line in dado:
            list_thre.append(line)
            thread.start_new_thread(nova_thread, (line,))

        while list_thre:
            pass

    except KeyboardInterrupt:
    	print('Done!')
       
