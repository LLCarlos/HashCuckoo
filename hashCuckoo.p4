/* -*- P4_16 -*- */
/***************************
HashCuckoo implementation in P4_v16
HashCuckoo is a mechanism for predicting programmable data plane elephant flows,
presented in the titled paper: "HashCuckoo: Predicting Elephant Flows using Meta-heuristics in Programmable Data Planes",
 submitted for IFIP Networking Conference 2022.

 Instructions for running this code are described in the HashCuckoo GitHub repository:
 https://github.com/HashCuckoo/HashCuckoo-IFIP-Networking

****************************/



#include <core.p4>
#include <v1model.p4>

      /*  Define Global constants */
const bit<8>  UDP_PROTOCOL = 0x11;
const bit<8>  TCP_PROTOCOL = 0x6;
const bit<16> TYPE_IPV4 = 0x800;
const bit<32> ID_CLONE = 42;
const bit<32> ID_CLONE_ALERT = 43;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  FLAG_EF        = 32; //00100000  //Elephant Flow
const bit<8>  FLAG_NF        = 20; //00100000  //Control


const bit<16> REG_SIZE        = 0xffff;   // Registers size

#define T  32   //Cell Size


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<48> timer_t;
typedef bit<32> size_tt;
typedef bit<8>  protocol_t;
typedef bit<16> port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>     version;
    bit<4>     ihl;
    bit<8>    diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>    flags;
    bit<13>  fragOffset;
    bit<8>    ttl;
    protocol_t  protocol;
    bit<16>    hdrChecksum;
    ip4Addr_t  srcAddr;
    ip4Addr_t  dstAddr;
}

header udp_t{
    port_t srcPort;
    port_t dstPort;
    bit<16> length;
    bit<16> checksumUdp;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
    bit<16> identif;
}

const bit<8> ICMP_ECHO_REQUEST = 8;
const bit<8> ICMP_ECHO_REPLY   = 0;

/*    Metadata Struct */
struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}


struct intrinsic_metadata_t {
    bit<1>  recirculate_flag;
}

struct metadata {
    @metadata @name("intrinsic_metadata")
    intrinsic_metadata_t intrinsic_metadata;
    
    size_tt thresholdBytes;
    timer_t timeOut;
    timer_t thresholdTime;
    ip4Addr_t ipSwitch;
    ip4Addr_t ipvAddr;
    port_t srcPort;
    port_t dstPort;
    bit<8> flagWhite;
    bit<8> flagEdge;
    bit<8> flagHost;
    bit<1> flagRecirculate;
}

struct headers {
    ethernet_t   ethernetController;
    ipv4_t       ipv4Controller;
    udp_t        updController;

    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
    udp_t        udp;
    tcp_t        tcp;
}

error { IPHeaderTooShort }


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser ParserImpl(packet_in packet,
out headers hdr,
inout metadata meta,
inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
   
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_ICMP : parse_icmp;
            UDP_PROTOCOL : parse_udp;
            TCP_PROTOCOL : parse_tcp;
            default      : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept; 
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_controller(macAddr_t srcAddr, macAddr_t dstAddr, ip4Addr_t ipSrc, ip4Addr_t ipDst,
                            port_t srcPort, port_t dstPort,  egressSpec_t port){

        hdr.ethernetController.setValid();
        hdr.ipv4Controller.setValid();
        hdr.updController.setValid();

        standard_metadata.egress_spec    = port;
        hdr.ethernetController.srcAddr   = srcAddr;
        hdr.ethernetController.dstAddr   = dstAddr;
        hdr.ethernetController.etherType = TYPE_IPV4;


        hdr.ipv4Controller.version        = hdr.ipv4.version;
        hdr.ipv4Controller.ihl            = hdr.ipv4.ihl;
        hdr.ipv4Controller.totalLen       = ((bit<16>)standard_metadata.packet_length) + 20+ 8;
        hdr.ipv4Controller.identification = 0;
        hdr.ipv4Controller.flags          = 0;
        hdr.ipv4Controller.fragOffset     = hdr.ipv4.fragOffset;
        hdr.ipv4Controller.ttl            = 64;
        hdr.ipv4Controller.srcAddr        = ipSrc;
        hdr.ipv4Controller.dstAddr        = ipDst;
        hdr.ipv4Controller.protocol       = UDP_PROTOCOL;

        if(hdr.ipv4.diffserv == 0){
            hdr.ipv4Controller.diffserv   = FLAG_NF; //Flag New FLow
        }else{
            hdr.ipv4Controller.diffserv   = hdr.ipv4.diffserv; //Flag Critical Flow Alert
        }

        hdr.updController.srcPort       = srcPort;
        hdr.updController.dstPort       = dstPort;
        hdr.updController.length        = ((bit<16>)standard_metadata.packet_length);
        hdr.updController.checksumUdp   = 0x0000;

    }

    action ipv4_forward(macAddr_t srcAddr, macAddr_t dstAddr, egressSpec_t port, bit<8> tos) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        if(tos != 50){
            hdr.ipv4.diffserv = tos; //Set flow type.
        }
    }

    /***********  TABLES ***********/
    table ipv4_lpm {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            meta.srcPort     : exact;
            meta.dstPort     : exact;
        }
        actions = {
            ipv4_forward;
            send_controller;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table ipv4_lpm_EF {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            meta.srcPort     : exact;
            meta.dstPort     : exact;
        }
        actions = {
            ipv4_forward;
            send_controller;
            //noPathEF;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    table icmp_lpm {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            hdr.icmp.identif : exact;
        }
        actions = {
            ipv4_forward;
            send_controller;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table icmp_lpm_EF {
        key = {
            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;
            hdr.ipv4.protocol: exact;
            hdr.icmp.identif : exact;
        }
        actions = {
            ipv4_forward;
            send_controller;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    action set_features(ip4Addr_t ipSwitch, bit<8> flag){
        meta.ipSwitch = ipSwitch;
        meta.flagEdge = flag;
    }

    table get_features {
        actions        = { set_features; NoAction; }
        default_action =  NoAction();
    }


    action set_threshold(timer_t timeOut, timer_t time, size_tt size){
        meta.timeOut     = timeOut;
        meta.thresholdTime  = time;
        meta.thresholdBytes = size;
    }

    table get_threshold {
        actions        = { set_threshold; NoAction; }
        default_action =  NoAction();
    }


    action set_flag_white(bit<8> flag){
        meta.flagWhite = flag;
    }

    table get_flag_white{
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
        }
        actions        = { set_flag_white; NoAction; }
        default_action =  NoAction();
    }

    action set_flag_host(bit<8> flag){
        meta.flagHost = flag;
    }

    table get_flag_host{
        key = {
            hdr.ethernet.srcAddr: ternary;
        }
        actions        = { set_flag_host; NoAction; }
        default_action =  NoAction();
    }


    /************************************
        Mechanism's Metadata Analysis
    ************************************/

    //*** REGISTERS ***//
    register<bit<1>> (0xffff) regsHashCuckoo;   //Hash-Cuckoo Register.
    register<bit<1>> (0xffff) regsHashCuckoo_2; //Hash-Cuckoo Register Backup.

    register<bit<1>> (0xffff) regsEF;           //Bloom Filter Register.
    register<bit<1>> (0xffff) regsEF_2;         //Bloom Filter Register Backup.

    /****************************
        Flow's Metadata Analysis
    ****************************/

    register<bit<32>>(0xffff) regsSizeFlow;     //Register to store the flow traffic volume.
    register<bit<48>>(0xffff) regsTimeFirst;    //Register to store the ingressTimeStamp of the flow frist packet.
    register<bit<48>>(0xffff) regsTimeLast;     //Register to store the ingressTimeStamp of the flow last packet.
    
    register<bit<32>>(0xffff) regsSizeFlow_2;   //Register to store the flow traffic volume.
    register<bit<48>>(0xffff) regsTimeFirst_2;  //Register to store the ingressTimeStamp of the flow frist packet.
    register<bit<48>>(0xffff) regsTimeLast_2;   //Register to store the ingressTimeStamp of the flow last packet.
    
    register<ip4Addr_t>(1) regsIpSwitch;        //Register to store the switch IP address.
    register<bit<8>>(1)    regsFlagEdge;        //Register to indicate if it is an edge switch.

    
    /****************************
                FLAGS
    ****************************/
    //Switch's metadata
    ip4Addr_t ipSwitch;
    bit<8> flagEdge;


    //Auxiliary variables for hash keys
    bit<32> keyCRC;
    bit<32> keyCSUM;
    bit<32> index;
    bit<1>  flagHC;
    bit<1>  flagHC_2;
    bit<1>  flagEF;
    bit<1>  flagEF_2;
    bit<1>  flagNF;
    bit<1>  flagNF_2;

    //Auxiliary variables to store the flow traffic volume
    bit<32> cont;
    bit<32> contSum;
    bit<32> cont_2;
    bit<32> contSum_2;
    
    //Auxiliary variables the flow packet time.
    bit<48> timeF;    //First packet timeStamp
    bit<48> timeL;    //Last packet timeStamp
    bit<48> timeC;    //Current packet timeStamp
    bit<48> timeF_2;
    bit<48> timeL_2;
    bit<48> timeC_2;
    

    /****************************
            MAIN PROCESS
    ****************************/
    apply {

        regsFlagEdge.read(flagEdge, 0);
        if(flagEdge == 0){
            get_features.apply();
            regsIpSwitch.write(0, meta.ipSwitch);
            regsFlagEdge.write(0, meta.flagEdge);
            flagEdge = meta.flagEdge;
        }

        if(hdr.ipv4.isValid()){

            //Checks whether the packet address is the current switch address.
            regsIpSwitch.read(ipSwitch, 0);
            if(hdr.ipv4.dstAddr == ipSwitch){
                //Control packet sent by controller for flow configuration. Recirculation necessary to proceed with the forwarding.     
                //Uncapsulates the original packet.
                hdr.ethernet.setInvalid();
                hdr.ipv4.setInvalid();                        
                hdr.udp.setInvalid();
                
                standard_metadata.recirculate_flag = 1;
                
            }else{

                get_threshold.apply();      //Get Threshholds
                get_flag_host.apply();   //Checks whether the packet comes from a host (ingress to network) or from a switch (network inside).
                flagNF   = 0;            //Aux flag to identification
                flagNF_2 = 0;            //Aux flag to identification
                meta.flagWhite = 0;      //Aux flag to control packet
                flagEF = 0;              //Aux flag to bloomFilter
                flagEF_2 = 0;            //Aux flag to bloomFilter
                flagHC = 0;              //Aux flag to HashCuckoo
                flagHC_2 = 0;            //Aux flag to HashCuckoo


                //*********  Valid paket process, get protocol, and Hash's ***********
                if(hdr.icmp.isValid()){
                    //ICMP Process
                    //*** 4-tuple hash key processing ***
                    hash(keyCRC, HashAlgorithm.crc16, (bit<16>)0,
                            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.icmp.identif}
                            , (bit<16>)112); //Get hash index by hash_CRC16.

                    hash(keyCSUM, HashAlgorithm.csum16, (bit<16>)0,
                            { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, hdr.icmp.identif}
                            , (bit<16>)112); //Get hash index by hash_CSUM16.
                }else{
                    //UDP or TCP Process
                    if(hdr.udp.isValid()){
                        meta.srcPort = hdr.udp.srcPort;
                        meta.dstPort = hdr.udp.dstPort;
                    }else{
                        if(hdr.tcp.isValid()){
                            meta.srcPort = hdr.tcp.srcPort;
                            meta.dstPort = hdr.tcp.dstPort;
                        }
                    }
                    //*** 5-tuple hash key processing ***
                    hash(keyCRC, HashAlgorithm.crc16, (bit<16>)0,
                        { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, meta.srcPort, meta.dstPort}
                        , (bit<16>)112); //Get hash index by hash_CRC16.

                    hash(keyCSUM, HashAlgorithm.csum16, (bit<16>)0,
                        { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol, meta.srcPort, meta.dstPort}
                        , (bit<16>)112); //Get hash index by hash_CSUM16.


                    //Check if it's a control flow indicated by a flagWhite.
                    get_flag_white.apply();
                }


                //************* Packet flags process *************//
                //flagEdge: if 2, indicates it is an edge switch, enable verification. Another case, just traditional forwarding.
                //flagHost: 1- indicates that it is an input flow from the host's mac.
                //flagHost: 0- indicates that it is a flow coming from the switch. does not calculate EF, because it was already calculated by another switch.
                //flagWhite: if 0, normal flow, enable verification. If 1, control flow, just traditional forwarding.
                //instance_type: If 0, indicates that it is a package not yet processed, not recirculated, not cloned.
                
                if(flagEdge == 2 &&  meta.flagHost == 1 && meta.flagWhite == 0 && standard_metadata.instance_type == 0){
                    
                    /******************************
                        EXTRACT PACKET METADATA     
                    ******************************/
                    
                    //IngressTimeStamp, epoch.
                    timeC = standard_metadata.ingress_global_timestamp; 
                    
                    //Read last packet times from each register.
                    regsTimeLast.read(timeL, keyCRC);       //Get the last packet time.
                    regsTimeLast.write(keyCRC, timeC);      //Update the last packet time.
                    
                    regsTimeLast_2.read(timeL_2, keyCSUM);  
                    regsTimeLast_2.write(keyCSUM, timeC);   
                    
                    /*******************************************************************************/

                    
                    /************************
                        CHECK NEW FLOW   
                    ************************/
                    //**Hash 1 varification**//
                    if(timeL == 0 || ((timeC-timeL) > meta.timeOut)){
                        //New Flow.
                        regsTimeFirst.write(keyCRC, timeC); //Set packet ingress timeStamp.
                        flagNF = 1;   //New Flow flag.
                        hdr.ipv4.diffserv = 0;
                    }
                    regsTimeFirst.read(timeF, keyCRC);   //Get the ingress time of the flow first packet. 

                    //**Hash 2 Verification**// 
                    if(timeL_2 == 0 || ((timeC-timeL_2) > meta.timeOut)){
                        regsTimeFirst_2.write(keyCSUM, timeC);
                        flagNF_2 = 1;
                        hdr.ipv4.diffserv = 0;
                    }
                    regsTimeFirst_2.read(timeF_2, keyCSUM);
                    /***************************************************/



                    /*************************
                        Flow Size Process
                    **************************/
                    //Hash 1
                    if(flagNF == 1){  //If new flow
                        cont = 0;
                    }else{
                        regsSizeFlow.read(cont, keyCRC);     //Read the current value from the register for that hash 1 key.
                    }
                    contSum  =  ((bit<32>)hdr.ipv4.totalLen) + 14 + cont; //Increments to current packet size.
                    //***Update Hash 1 flow size***//
                    regsSizeFlow.write(keyCRC, contSum);     //Stores the updated value for the key in the register.
                    
                    //Hash 2
                    if(flagNF_2 == 1){
                        cont_2 = 0;
                    }else{
                        regsSizeFlow_2.read(cont_2, keyCSUM);   //Read the current value from the register for that hash 2 key.
                    }
                    contSum_2  =  ((bit<32>)hdr.ipv4.totalLen) + 14 + cont_2; //Increments to current packet size.
                    //***Update Hash 2 flow size***//
                    regsSizeFlow_2.write(keyCSUM, contSum_2);   //Stores the updated value for the key in the register.
                    
                    /***********************************************************/

                     
                    /********************************
                            Select Flow Features
                    ********************************/
                    //**Verificacao dos valores.
                    //For flow size, choose the smallest.
                    if(contSum_2 < contSum){  
                        contSum = contSum_2;  
                    }

                    //For the start time, select the most recent, choose the highest value. 
                    //This choice ensures that in the worst case false positives will occur over false negatives.
                    //If the preference is for false negatives over false positives, choose the smallest.
                    if(timeF_2 > timeF){
                        timeF = timeF_2;
                    }
                    /*************************************************************/



                    /*******************************************
                                FLOW ANALYSIS
                        Bloom Filter Indentification Control
                    *********************************************/
                    //Hash 1
                    if(flagNF == 1){
                        regsHashCuckoo.read(flagHC, keyCRC);
                        regsEF.write(keyCRC, 0);
                    }else{
                        regsEF.read(flagEF, keyCRC);
                    }

                    //Hash2
                    if(flagNF_2 == 1){
                        regsHashCuckoo_2.read(flagHC_2, keyCSUM);
                        regsEF_2.write(keyCSUM, 0);
                    }else{
                        regsEF_2.read(flagEF_2, keyCSUM);
                    }


                    /*******************************
                       Hash Cuckoo analysis
                    ********************************/
                    if(flagHC == 1 && flagHC_2 == 1){
                        flagEF   = flagHC;                  //Antecipated identification
                        flagEF_2 = flagHC_2;                //Antecipated identification
                        regsEF.write(keyCRC, flagEF);       //Set BloomFilter new identification. 
                        regsEF_2.write(keyCSUM, flagEF_2);  //Backup BloomFilter.
                        // hdr.ipv4.diffserv = FLAG_EF;          //Crital flow alert to prediction module.
                        //Clone to alert LWR analysis....
                        //clone(CloneType.I2E, ID_CLONE_ALERT);  //Clone to critical flow alert.

                        /******************************************************************************
                          The clone is not needed as it is the first packet in the flow, 
                          so there is no forwarding rule installed (4-tuple or 5-tuple). 
                          Thus, the packet will already be forwarded to the route configuration unit. 
                          Just indicate that it is a critical flow, using the control flag.
                          ******************************************************************************/
                    }
                        
                    //Bloom filter control previous identification.
                    if(flagEF == 1 && flagEF_2 == 1){
                        hdr.ipv4.diffserv = FLAG_EF;         //Set header's identification flag to network mitigation.
                    }else{
                        if((timeC-timeF) > meta.thresholdTime && contSum > meta.thresholdBytes){   //Check Thresholds.
                            /*********************************
                              ELEPHANT FLOW  IDENTIFICATED 
                            ***********************************/
                            clone(CloneType.I2E, ID_CLONE);  //Clones the packet to generate the controller report.
                            regsEF.write(keyCRC, 1);         //Set BloomFilter new identification. 
                            regsEF_2.write(keyCSUM, 1);      //Backup BloomFilter.
                            hdr.ipv4.diffserv = FLAG_EF;     //Set header's identification flag to network mitigation.
                        }
                    }
                    /****************************************************************************/
                }


                /***********************************
                    Packet Forwarding, Flow Tables
                ***********************************/
                if(hdr.ipv4.diffserv == 0 || meta.flagWhite == 1){
                    //Non Mitigate flow, or controler flow (flagWhite == 1), flowding to default path.
                    if(hdr.icmp.isValid()){
                        icmp_lpm.apply();  //ICMP (4-tuple) Flow Table. Long prefix match.
                    }else{
                        ipv4_lpm.apply();  //TPC/UDP (5-tuple) Flow Table. Long prefix match.
                    }
                }else{
                    //************ Mitigate ************//
                    //Elephant Flow. Routing to alternative path.
                    if(hdr.icmp.isValid()){
                        icmp_lpm_EF.apply();  //ICMP (4-tuple) Flow Table. Long prefix match.
                    }else{
                        ipv4_lpm_EF.apply();  //TPC/UDP (5-tuple) Flow Table. Long prefix match.
                    }
                }

                /*****************************************************************************/
            }
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action send_controller_EF(macAddr_t srcAddr, macAddr_t dstAddr, ip4Addr_t ipSrc, ip4Addr_t ipDst,
                            port_t srcPort, port_t dstPort){
        hdr.ethernetController.setValid();
        hdr.ipv4Controller.setValid();
        hdr.updController.setValid();

        //standard_metadata.egress_spec    = port;
        hdr.ethernetController.srcAddr    = srcAddr;
        hdr.ethernetController.dstAddr    = dstAddr;
        hdr.ethernetController.etherType  = TYPE_IPV4;

        hdr.ipv4Controller.version        = hdr.ipv4.version;
        hdr.ipv4Controller.ihl            = hdr.ipv4.ihl;
        hdr.ipv4Controller.diffserv       = FLAG_EF; //Control flow flag.
        hdr.ipv4Controller.totalLen       = ((bit<16>)standard_metadata.packet_length) + 20+8; //Packet + ipvHeader + udpHeader
        hdr.ipv4Controller.identification = 0;
        hdr.ipv4Controller.flags          = 0;
        hdr.ipv4Controller.fragOffset     = hdr.ipv4.fragOffset;
        hdr.ipv4Controller.ttl            = 64;
        hdr.ipv4Controller.srcAddr        = ipSrc;
        hdr.ipv4Controller.dstAddr        = ipDst;
        hdr.ipv4Controller.protocol       = UDP_PROTOCOL;

        hdr.updController.srcPort       = srcPort;
        hdr.updController.dstPort       = dstPort;
        hdr.updController.length        = ((bit<16>)standard_metadata.packet_length)+8;
        hdr.updController.checksumUdp   = 0x0000;
                
    }


    table map_controller{
        actions        = { send_controller_EF;  NoAction; }
        default_action =  NoAction();

    }

    apply {
        if(standard_metadata.instance_type == 1){  //Indicates that it is an ingress clone, to "generate" the report packet to be sent to the controller. 
            map_controller.apply();
        }
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/


control computeChecksum(
    inout headers  hdr,
    inout metadata meta)
{
    apply {
        
            update_checksum(hdr.ipv4Controller.isValid(),
            {  hdr.ipv4Controller.version,
                hdr.ipv4Controller.ihl,
                hdr.ipv4Controller.diffserv,
                hdr.ipv4Controller.totalLen,
                hdr.ipv4Controller.identification,
                hdr.ipv4Controller.flags,
                hdr.ipv4Controller.fragOffset,
                hdr.ipv4Controller.ttl,
                hdr.ipv4Controller.protocol,
                hdr.ipv4Controller.srcAddr,
                hdr.ipv4Controller.dstAddr
            },
            hdr.ipv4Controller.hdrChecksum, HashAlgorithm.csum16);
        

            update_checksum(
                hdr.ipv4.isValid(),
                    { hdr.ipv4.version,
                      hdr.ipv4.ihl,
                      hdr.ipv4.diffserv,
                      hdr.ipv4.totalLen,
                      hdr.ipv4.identification,
                      hdr.ipv4.flags,
                      hdr.ipv4.fragOffset,
                      hdr.ipv4.ttl,
                      hdr.ipv4.protocol,
                      hdr.ipv4.srcAddr,
                      hdr.ipv4.dstAddr },
                    hdr.ipv4.hdrChecksum,
                    HashAlgorithm.csum16);       
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernetController);
        packet.emit(hdr.ipv4Controller);
        packet.emit(hdr.updController);

        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp); 
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
ParserImpl(),
verifyChecksum(),
ingress(),
egress(),
computeChecksum(),
DeparserImpl()
) main;


