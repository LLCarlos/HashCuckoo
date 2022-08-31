#-*- coding: UTF-8 -*-
#Switch tables update by CLI


import subprocess


class UpdateSwitches():

    def __init__(self, switches, edge, time, size, timeOut):
        self.switches = switches
        self.switches_edge = edge
        self.time  = time*(10**6)
        self.size  = size
        self.timeOut = timeOut*(10**6)


    def update(self):
        print("UPDATE_SWITCHES")

        for s in self.switches:
            pid = self.switches[s]
            if s in self.switches_edge:
                flagEdge = 2    #Edge Switch.
            else:
                flagEdge = 1    #Core Switch.

            arg = ['simple_switch_CLI', '--thrift-port', '%d'%(pid) ]
            print(arg)
            ipSwitch = '10.0.%d.9'%(int(s[1:]))

            p = subprocess.Popen(arg, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            command = 'table_set_default get_features set_features %s %d'%(ipSwitch, flagEdge)
            command = command +'\n'+ 'table_set_default get_threshold set_threshold %d %d %d'%(self.timeOut, self.time, self.size)
         
            command = command +'\n'+ 'table_set_default get_flag_white set_flag_white 0'
            command = command +'\n'+ 'table_add get_flag_white set_flag_white  0x00000009&&&0x0000000f 0x00000000&&&0x00000000 => 1 1'
            command = command +'\n'+ 'table_add get_flag_white set_flag_white  0x00000000&&&0x00000000 0x00000009&&&0x0000000f => 1 1'
           
            command = command +'\n'+ 'table_set_default get_flag_host set_flag_host 0'
            command = command +'\n'+ 'table_add get_flag_host set_flag_host 0x000400000000&&&0xffff00000000 => 1 1'

            out, error = p.communicate(command)
            


#Begin.
if __name__ == '__main__':
    THRESHOLD_TIME = 10     
    TIME_OUT    = 5     
    THRESHOLD_SIZE = 10000  

    print ('Start Updates')
    switches = {}
    obj = UpdateLiminar(switches, THRESHOLD_TIME, THRESHOLD_SIZE, TIME_OUT) 
    obj.update()
