#-*- coding: UTF-8 -*-

import sys
import subprocess
path = 'topology_net.py'

HOP_VALUE = 1
FLAG_EF    = 32

class Flow():

    def __init__(self, node=None):
        self.G = {} #Grafo
        self.switch = None
        self.mac_to_port = None
        self.EF = {}
        self.flows = {}
        self.table_switch = {}
        self.switches_edge = {}
        self.hosts = {}
        self.routes = {}
        self.routesEF = {}

        self.controller = node

        self.D = {}  
        self.Pi = {} 
        
        self.arq_flow   = open('./logs/log_flow.csv', 'w')
        self.arq_flowEF = open('./logs/log_flowEF.csv', 'w')
        
        self.parser_topology(path)
        self.show_graph()

        self.set_edge()

        self.setController(self.controller)
        self.calcRoutes()



    #Function to learn network topology
    def parser_topology(self, path, flagRoutes=False):
        arq = open(path)
        data = None

        if arq:
            data = arq.readlines()

        if data is not None:
            for line in data:
                n1, n2 = line.split('<->')   #Split node1 to node2: "h1-eth0<->s1-eth1 (OK OK)"
                n2 = n2.split()[0]           #Split "s1-eth1'' from "s1-eth1 (OK OK)"
                n1, port1 = n1.split('-eth') #Split node name: s1; node iface: 1
                n2, port2 = n2.split('-eth')
                if (n1 == self.controller or n2 == self.controller) == False:
                    if n1[0] == 'h' and flagRoutes == False:
                        self.add_host(n1)
                    if n2[0] == 'h' and flagRoutes == False:
                        self.add_host(n2)
                    self.add_link(n1, int(port1), n2, int(port2)) #Set link int the graph
            if flagRoutes == False:
                self.add_switches() #Add switches in the control flow


    #Get host/switches IP and MAC address
    def add_host(self, host):
        if host not in self.hosts.keys():
            host_ip = '10.0.%s.10'%(host[1:])
            host_mac = '00:04:00:00:00:%02x'%(int(host[1:]))

            self.hosts[host] = {'ip': host_ip, 'mac':host_mac, 'D':{}, 'Pi':{}}

    def getIpCpntroller(self):
        if(self.controller):
            host_ip = '10.0.%s.10'%(self.controller[1:])
            return host_ip
        else:
            return None
            

    #Inset switch' links into route graph
    def add_switches(self):
        nodes = self.G.keys()
        nodes.sort()
        for s in nodes:
            if s[0] == 's':
                cont = len(self.table_switch)
                self.table_switch[s] = (9090+int(s[1:]) -1)

    #switch parser from topology
    def set_edge(self):
        arq = open(path)
        data = None

        if arq:
            data = arq.readlines()

        if data is not None:
            for line in data:
                n1, n2 = line.split('<->')   
                n2 = n2.split()[0]           
                port1 = n1 
                port2 = n2
                n1, a = n1.split('-eth') 
                n2, b = n2.split('-eth')

                if (n1 == self.controller or n2 == self.controller):
                    if n1[0] == 'h':
                        self.switches_edge[n2] = port2

                    if n2[0] == 'h':
                        self.switches_edge[n1] = port1

    #Switches list
    def list_switches(self):
        list_s = self.table_switch.keys()
        list_s.sort()
        return list_s

    def getSwitches(self):
        if len(self.table_switch.keys()) > 0:
            return self.table_switch
        return None

    def getEdge(self):
        if(len(self.switches_edge.keys()) > 0):
            return self.switches_edge
        return None

    def add_link(self, node1, port1, node2, port2):
        #Insert a -> b link
        if (node1 not in self.G):
            self.G[node1] = {} 
        self.G[node1][node2] = port1  

        #Insert a <- b link
        if (node2 not in self.G):
            self.G[node2] = {}
        self.G[node2][node1] = port2
    

    def show_graph(self):
        print("")
        nodes = self.G.keys()
        nodes.sort()
        for k in nodes:
            print (k, '->',self.G[k])


    def setController(self, host):
        if self.controller:
            print '\nSet Controller..'
            print '... set route controller switches...'
            for s in self.table_switch.keys():
                if s in self.switches_edge.keys():
                    port = self.switches_edge[s]
                    port = port.split('-eth')[1]
                    self.set_default(self.controller, s, int(port))
            print '...Done!'
            

    def set_default(self, host, switch, out_port):
        udp_port = 4321     #Switch-controller communication port
        ipHost = '10.0.%s.10'%(host[1:])
        mac_dst = '00:04:00:00:00:%02x'%(int(host[1:]))

        mac_src  = "00:aa:00:%02x:00:%02x"%(int(switch[1:]),int(host[1:]))
        ipSwitch = '10.0.%d.9'%(int(switch[1:]))

        port_switch = self.table_switch[switch] 
        arg = ['simple_switch_CLI', '--thrift-port', str(port_switch) ]

        tupla = (mac_src, mac_dst, ipSwitch, ipHost, udp_port, udp_port, out_port)

        p = subprocess.Popen(arg, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        command = 'table_set_default ipv4_lpm send_controller %s %s %s %s %d %d %d'%tupla
        command = command + '\ntable_set_default ipv4_lpm_EF send_controller %s %s %s %s %d %d %d'%tupla

        command = command + '\ntable_set_default icmp_lpm send_controller %s %s %s %s %d %d %d'%tupla
        command = command + '\ntable_set_default icmp_lpm_EF send_controller %s %s %s %s %d %d %d'%tupla

        command = command + '\ntable_set_default map_controller send_controller_EF %s %s %s %s %d %d \nmirroring_add 42 %d'%tupla

        out, error = p.communicate(command)


    ###########################################
    #####       Traffic Engineering        ####
    ###########################################

    def calcRoutes(self):
        for host in self.hosts:
            self.routes[host]   = {}
            self.routesEF[host] = {}
            self.D = {}
            self.Pi = {}
            #self.show_graph()
            flagHost = None

            self.dijkstra(host)
            for h in self.hosts.keys():         
                if h is not host  and h in self.D.keys():       
                    self.routes[host][h] = self.BPP(host, h)    
                    if h != self.controller:
                        s1 = self.routes[host][h][len(self.routes[host][h])-2]
                        s2 = self.routes[host][h][len(self.routes[host][h])-3]
                        del self.G[s1][s2]
                        del self.G[s2][s1]
                        if flagHost is None:
                            flagHost = h

            if  flagHost:
                s1 = self.routes[host][flagHost][1]
                s2 = self.routes[host][flagHost][2]
                del self.G[s1][s2]
                del self.G[s2][s1]

            self.D = {}
            self.Pi = {}
            self.dijkstra(host)

            for h in self.hosts.keys():         
                if h is not host  and h in self.D.keys():          
                    self.routesEF[host][h] = self.BPP(host, h)    

            self.G = {}
            self.parser_topology(path, True)


    def newFlow(self, ipSrc, ipDst,  proto, tupla):
        if tupla not in self.flows.keys():
            src = self.getHost_IP(ipSrc)
            dst = self.getHost_IP(ipDst)

            route = self.getRoute(src, dst) #Check if there is a calculated route between src-dst.
            print src,'->',dst
            if(route is not None):
                self.flows[tupla] = list(route)
                switch = route[1]
                h2  = route[2]
                n1  = route.pop()
                n2  = route.pop()
                self.insert_flow_A(dst, src, n1, n2, tupla, route)

                data = ''
                for i in tupla:
                    data =  data + '%s,'%(str(i))
                data =  data + '%s-eth%d,%s-eth%d\n'%(switch, self.G[switch][src], switch, self.G[switch][h2])
                self.arq_flow.write(data)

                return True
            else:
                return False
        else:
            print('Flow already processed')
        return False

    #Mitigation Path
    def upFlow(self, ipSrc, ipDst, proto, tupla):

        if tupla not in self.EF.keys():
            src = self.getHost_IP(ipSrc)
            dst = self.getHost_IP(ipDst)

            route = self.getRouteEF(src, dst)  
            if(route is not None):
                n1  = route.pop()
                n2  = route.pop()
                self.insert_flow_A(dst, src, n1, n2, tupla, route, flag_EF = True)
                return True
            else:
                if(src != None and dst != None):
                    self.D = {}
                    self.Pi = {}
                    self.show_graph()
                    self.dijkstra(src)
                    if dst in self.D.keys():
                        route = self.BSP(src, dst)
                        n1  = route.pop()
                        n2  = route.pop()
                        self.insert_flow_A(dst, src, n1, n2, tupla,  route, flag_EF = True)
                        return True
        return False


    #Standard/shortest path
    def getRoute(self, src, dst):
        if( src in self.routes.keys()):
            if(dst in self.routes[src].keys()):
                return list(self.routes[src][dst])
        return None

    #Alternative path   (Mitigation)
    def getRouteEF(self, src, dst):
        if( src in self.routesEF.keys()):
            if(dst in self.routesEF[src].keys()):
                return list(self.routesEF[src][dst])
        return None


    def insertEF(self, tupla):
        self.EF[tupla] = []

        src = self.getHost_IP(tupla[0])
        dst = self.getHost_IP(tupla[1])
        route = self.getRouteEF(src, dst)  
        switch = route[1]
        h2  = route[2]
        data = ''
        for i in tupla:
            data =  data + '%s,'%(str(i))
        data =  data + '%s-eth%d,%s-eth%d\n'%(switch, self.G[switch][src], switch, self.G[switch][h2])
        self.arq_flowEF.write(data)


    def getEF_List(self, tupla):
        if tupla in self.EF.keys():
            return True
        else:
            return False
    

    def getHost_IP(self, ipv4):
        for k in self.hosts.keys():
            if(self.hosts[k]['ip'] == ipv4):
                return k
        return None


    #Route calculator based on dijkstra's algorithm
    def dijkstra(self, node):

        nodes = self.G.keys()
        nodes.sort()
        visit = nodes   

        #Process each node and the distance to neighbors, assigning the shortest path.
        while True:
            if (node in self.D.keys()) == False:
                self.D[node] = {}  
                self.D[node][0] = [node]

            min_node = min(self.D[node].keys())
            for v in self.G[node].keys():
                if  v in self.D.keys():
                    if v in visit: 
                        cust = min_node + HOP_VALUE 
                        if cust in self.D[v].keys():
                            self.D[v][cust].append(node)
                        else:
                             self.D[v][cust] = [node]
                    else:
                        pass
                else:
                    #Update.
                    self.D[v] = {}
                    cust = min_node + HOP_VALUE 
                    self.D[v][cust] = [node]

            #Search for the node with the shortest distance
            aux_dist = None
            aux_node = None
            visit.remove(node)
            for i in visit:
                if i in self.D.keys():
                    min_node  = min(self.D[i].keys())
                    if aux_dist == None or aux_dist > min_node:
                        aux_dist = min_node
                        aux_node = i

            if aux_node == None:
                break

            node = aux_node


        self.print_dijkstra()


    #Best Alternative Path
    def BSP(self, src, dst):
        bapList = [dst]
        while  True:
            nodes = self.D[dst].keys()
            nodes.sort()
            if len(nodes) > 1:
                nodes = self.D[dst][nodes[1]]
            else:
                nodes = self.D[dst][nodes[0]]
            if len(nodes) > 1:
                node = nodes[1]
            else:
                node = nodes[0]
            bapList.insert(0,node)
            if node == src:
                break
            else:
                dst = node
        return bapList

    #Best Path, shortes
    def BPP(self, src, dst):
        bapList = [dst]
        while  True:
            ind = min(self.D[dst].keys())
            node = self.D[dst][ind][0]
            bapList.insert(0,node)
            if node == src:
                break
            else:
                dst = node
        return bapList


    #Print path algorithm
    def print_dijkstra(self):
        nodes = self.D.keys()
        nodes.sort()
        print ('\nDijkstra\n')
        for k in nodes:
            print (k, self.D[k])


    #Set the path (link) hop on the switch's flow table
    def insert_flow_A(self, dst, src, n1, n2, tupla, bap = None, flag_set_controller=False, flag_invert_direct=False, flag_EF=False):
        if(flag_EF == True):
            difServ = FLAG_EF    #Mitigation path
        else:
            difServ = 0          #Default path
        
        if(flag_set_controller == True):
            difServ = 50         #Control path

        if n2 in self.table_switch.keys():
            
            #Select the output port and destination mac
            out_port  = self.G[n2][n1] 

            #Checks whether the destination is a host or a switch
            if n1 in self.hosts.keys():
                #Performs a MAC address lookup in the host's table.
                mac_src = "00:aa:00:%02x:00:%02x"%(int(n2[1:]),int(n1[1:]))
                mac_dst = self.hosts[n1]['mac'] #host: 'h1', 'h2'... 'hn'
                
                if flag_set_controller is False: 
                    difServ = 0 
            else:
                #Switch src and dst
                mac_src = "00:aa:00:%02x:%02x:00"%(int(n2[1:]),int(n1[1:]))
                mac_dst = "00:aa:00:%02x:%02x:00"%(int(n1[1:]),int(n2[1:]))

            ##Insert flow path role 
            self.add_flow( n2, tupla, mac_src, mac_dst, out_port, difServ, flag_set_controller,flag_EF)

            #Checks if there is a secondary route established.
            if(flag_set_controller is True):
                if(flag_invert_direct == True):
                    min_key  = min(self.D[n1].keys())
                    n2 = self.D[n1][min_key][0]    #first reach for 'n1'
                    self.insert_flow_A(dst, src, n2, n1, tupla, bap, flag_set_controller, flag_invert_direct, flag_EF)
                else: 
                    min_key  = min(self.D[n2].keys())
                    n1 = self.D[n2][min_key][0]    #first reach for 'n2'
                    self.insert_flow_A(dst, src, n2, n1, tupla, bap, flag_set_controller, flag_invert_direct, flag_EF)
            else:
                if bap:
                    n1 = bap.pop()
                else:
                    min_key  = min(self.D[n2].keys())
                    n1 = self.D[n2][min_key][0]    #primeiro alcanse para 'n2'
                self.insert_flow_A(dst, src, n2, n1, tupla, bap, flag_set_controller, flag_invert_direct, flag_EF)


    #Function to add forwarding rule to switch flow table
    def add_flow(self, switch, tupla, mac_src, mac_dst, out_port, flag_ToS, flag_set_controller=False, flag_EF=False):
        port_switch = self.table_switch[switch] #Switch communitacion port.
        match = ""
        arg = ['simple_switch_CLI', '--thrift-port', str(port_switch) ]
        
        p = subprocess.Popen(arg, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if tupla:
            for data in tupla:
                if data is not None:
                    match = match + " " + str(data)
            if(len(tupla) == 5):
                table = 'ipv4_lpm'
            if(len(tupla) == 4):
                table = 'icmp_lpm'
        if(flag_EF is True):
            table = table+'_EF'
        command = 'table_add %s ipv4_forward %s  => %s %s %d %d'%(table, match, mac_src, mac_dst, out_port, flag_ToS)
        out, error = p.communicate(command)
        
