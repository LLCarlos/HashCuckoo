# HashCuckoo: Predicting Elephant Flows using Meta-heuristics in Programmable Data Planes
This repository contains the implementation and metadata of the HashCuckoo prototype presented in the paper submitted to IFIP Networking Conference 2022. We will include additional information after the [IFIP Networking Conference 2022](https://networking.ifip.org/2022/) review process.


___________________________

This repository contains the scripts used in the prototype and experimental evaluation, as described below:<br/>
`control.py`          - Switch-controller communication interface.<br/>
`flowManager.py`      - SDN-Controller and traffic manager for IXP network.<br/>
`hahsCuckoo.p4`       - Programmable P4_16 Switch. <br/>
`p4app.json`          - Pointer for P4 application and topology.<br/>
`startTshark`         - Tshak commands to generate the `pcap` experiment log.<br/>
`topology_net`        - Mapping the infrastructure to the controller.<br/>
`updateSwitches.py`   - P4 CLI configuration and update switches.<br/>

### Folders: 
`figures`   - Paper's Figures.<br/>
`utils`     - Additional files for the P4 prototype and analysis of the experiments.<br/>
`workload`  - Experimental Workload.<br/>


To run:<br/>
- After installing P4 environment (https://github.com/p4lang)<br/>

1. Start P4 topology mininet:
```
bash ./run.sh
```

2. Start Controller/Sniffer:
```
python control.py
```

3. Start tshark sniffer:
```
bash start_tshark.py
```

4. Start workload:
```
python ./workload/start_workload.py
```
* Alternatively, we recommend using ping to test hosts communication, for example:
```
mininet> h1 ping h2
```


