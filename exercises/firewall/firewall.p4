/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


/* CONSTANTS */

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_LLDP = 0x88cc;
const bit<8>  TYPE_ICMP = 0x01;
const bit<8>  TYPE_TCP  = 0x06;
const bit<8>  TYPE_UDP = 0x11;


#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1
#define MAX_ID 1<<16

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t{
    bit<16> usrcPort;
    bit<16> udstPort;
    bit<16> ulength;
    bit<16> uchecksum;
}

header dns_t{
    bit<16> dlength;
    bit<16> transid;
    bit<1>  dqr;
    bit<4>  dopcode;
    bit<1>  daa;
    bit<1>  dtc;
    bit<1>  drd;
    bit<1>  dra;
    bit<1>  dz;
    bit<1>  dad;
    bit<1>  dcd;
    bit<4>  drcode;
    bit<16> dqdcount;
    bit<16> dancount;
    bit<16> dnscount;
    bit<16> darcount;
    
}

header icmp_t{
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    bit<32> rest;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    icmp_t       icmp;
    tcp_t        tcp;
    udp_t        udp;
    dns_t	     dns;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
	        TYPE_UDP: udp;
            TYPE_ICMP: icmp;
            default: accept;
        }
    }

    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }
    state udp {
       packet.extract(hdr.udp);
       packet.extract(hdr.dns);
       transition accept;
    }

    state icmp{
        packet.extract(hdr.icmp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    
    //added variables below 


    register<bit<32>>(1) syn_counter;
    register<bit<32>>(1) ack_counter;
    register<bit<32>>(1) udp_counter;
    register<bit<32>>(1) icmp_counter;
    register<bit<32>>(1) synack_counter;
    register<bit<32>>(1) dns_count;
    register<bit<32>>(1) limit;

    register<bit<32>>(1) total_packet;
    register<bit<32>>(1) dropped;




  
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action update_syn (){
        bit<32> tmp_syn;
        syn_counter.read(tmp_syn,0);
        syn_counter.write(0,tmp_syn+1);
    }

    action update_ack (){
        bit<32> tmp_ack;
        ack_counter.read(tmp_ack,0);
        ack_counter.write(0,tmp_ack+1);
    }

    action update_udp(){
        bit<32> tmp_udp;
        udp_counter.read(tmp_udp,0);
        udp_counter.write(0,tmp_udp+1);
    }

    action update_icmp(){
        bit<32> tmp_icmp;
        icmp_counter.read(tmp_icmp,0);
        icmp_counter.write(0,tmp_icmp+1);
    }

    action update_synack(){
        bit<32> tmp_synack;
        synack_counter.read(tmp_synack,0);
        synack_counter.write(0,tmp_synack+1);
    }

    table count_syn{
        key={
            hdr.tcp.syn : exact;
        }
        actions={
            update_syn;
            NoAction;
        }
        default_action = NoAction();
    }

    table count_ack{
        key={
            hdr.tcp.ack : exact;
        }
        actions={
            update_ack;
            NoAction;
        }
        default_action = NoAction();
    }

    table count_synack{
        key={
            hdr.tcp.syn : exact;
            hdr.tcp.ack : exact;
        }
        actions={
            update_synack;
            NoAction;
        }
        default_action = NoAction();
    }

    action dns_question(){
        bit<32> tmp_dns;
        //#bit<32> hash_t;
        //#hash_t = (bit<32>)hdr.dns.transid % 101;
        dns_count.read(tmp_dns,0);
        dns_count.write(0,tmp_dns+1);
    }

    

    action dns_answer(){
        bit<32> tmp_dns;
        //#bit<32> hash_t;
	    //#hash_t = (bit<32>)hdr.dns.transid % 101;
        dns_count.read(tmp_dns,0);
        dns_count.write(0,tmp_dns-1);
    }

    table dns_table{
        key={
            hdr.dns.dqr : exact;
        }
        actions={
            dns_question;
            dns_answer;
            NoAction;
        }
        default_action = NoAction();
    }
    


    
    apply {
        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();
            if (hdr.tcp.isValid()){
                bit<32> tmp_totalpacket;
                total_packet.read(tmp_totalpacket,0);
                total_packet.write(0,tmp_totalpacket+1);

                //syn_ack
                count_synack.apply();
                bit<32> tmp_synack;
                bit<32> tmp_limit;
                limit.read(tmp_limit,0);

                synack_counter.read(tmp_synack,0);
                if(tmp_synack>tmp_limit){
                    drop();
                    bit<32> drop_tmp;
                    dropped.read(drop_tmp,0);
                    dropped.write(0,drop_tmp+1);
                }


                //syn flood
                count_syn.apply();
                count_ack.apply();

                bit<32> tmp_ack;
                bit<32>tmp_syn;
                
                ack_counter.read(tmp_ack,0);
                syn_counter.read(tmp_syn,0);
                if(tmp_syn-tmp_ack > tmp_limit){
                    drop();
                    bit<32> drop_tmp;
                    dropped.read(drop_tmp,0);
                    dropped.write(0,drop_tmp+1);
                }

                
            }
            else if(hdr.udp.isValid()){
                bit<32> tmp_totalpacket;
                total_packet.read(tmp_totalpacket,0);
                total_packet.write(0,tmp_totalpacket+1);
                //DNS Amplification
                dns_table.apply();
                bit<32> tmp_dns;
                dns_count.read(tmp_dns,0);
                if(tmp_dns<=0){
                    drop();
                    bit<32> drop_tmp;
                    dropped.read(drop_tmp,0);
                    dropped.write(0,drop_tmp+1);
                }

                //UDP Flood
                update_udp();
                
                bit<32> tmp_udp;
                bit<32> tmp_udp_limit;
                limit.read(tmp_udp_limit,0);
                udp_counter.read(tmp_udp,0);
                if(tmp_udp>tmp_udp_limit){
                    drop();
                    bit<32> drop_tmp;
                    dropped.read(drop_tmp,0);
                    dropped.write(0,drop_tmp+1);
                }

            }
            else if (hdr.icmp.isValid()){
                bit<32> tmp_totalpacket;
                total_packet.read(tmp_totalpacket,0);
                total_packet.write(0,tmp_totalpacket+1);
                //icmp flood
                update_icmp();
                bit<32> tmp_icmp;
                bit<32> tmp_icmp_limit;
                limit.read(tmp_icmp_limit,0);
                icmp_counter.read(tmp_icmp,0);
                if(tmp_icmp>tmp_icmp_limit){
                    drop();
                    bit<32> drop_tmp;
                    dropped.read(drop_tmp,0);
                    dropped.write(0,drop_tmp+1);
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
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

control MyDeparser(packet_out packet, in headers hdr) {


    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.dns);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
