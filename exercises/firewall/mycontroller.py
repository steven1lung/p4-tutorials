#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
from time import sleep
from datetime import datetime
from scapy.contrib import lldp
# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

#import runtime_CLI
import runtime_CLI


SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def enum(type_name, *sequential, **named):
    enums = dict(list(zip(sequential, list(range(len(sequential))))), **named)
    reverse = dict((value, key) for key, value in enums.items())

    @staticmethod
    def to_str(x):
        return reverse[x]
    enums['to_str'] = to_str

    @staticmethod
    def from_str(x):
        return enums[x]

    enums['from_str'] = from_str
    return type(type_name, (), enums)


PreType = enum('PreType', 'none', 'SimplePre', 'SimplePreLAG')
MeterType = enum('MeterType', 'packets', 'bytes')
TableType = enum('TableType', 'simple', 'indirect', 'indirect_ws')
ResType = enum('ResType', 'table', 'action_prof', 'action', 'meter_array',
               'counter_array', 'register_array', 'parse_vset')


def writeTunnelRules(p4info_helper, ingress_sw, egress_sw, tunnel_id,
                     dst_eth_addr, dst_ip_addr):
    """
    Installs three rules:
    1) An tunnel ingress rule on the ingress switch in the ipv4_lpm table that
       encapsulates traffic into a tunnel with the specified ID
    2) A transit rule on the ingress switch that forwards traffic based on
       the specified ID
    3) An tunnel egress rule on the egress switch that decapsulates traffic
       with the specified ID and sends it to the host

    :param p4info_helper: the P4Info helper
    :param ingress_sw: the ingress switch connection
    :param egress_sw: the egress switch connection
    :param tunnel_id: the specified tunnel ID
    :param dst_eth_addr: the destination IP to match in the ingress rule
    :param dst_ip_addr: the destination Ethernet address to write in the
                        egress rule
    """
    # 1) Tunnel Ingress Rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr, 32)
        },
        action_name="MyIngress.myTunnel_ingress",
        action_params={
            "dst_id": tunnel_id,
        })
    ingress_sw.WriteTableEntry(table_entry)
    print ("Installed ingress tunnel rule on %s" % ingress_sw.name)

    # 2) Tunnel Transit Rule
    # The rule will need to be added to the myTunnel_exact table and match on
    # the tunnel ID (hdr.myTunnel.dst_id). Traffic will need to be forwarded
    # using the myTunnel_forward action on the port connected to the next switch.
    #
    # For our simple topology, switch 1 and switch 2 are connected using a
    # link attached to port 2 on both switches. We have defined a variable at
    # the top of the file, SWITCH_TO_SWITCH_PORT, that you can use as the output
    # port for this action.
    #
    # We will only need a transit rule on the ingress switch because we are
    # using a simple topology. In general, you'll need on transit rule for
    # each switch in the path (except the last switch, which has the egress rule),
    # and you will need to select the port dynamically for each switch based on
    # your topology.

    # TODO build the transit rule
    # TODO install the transit rule on the ingress switch
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",
        match_fields={
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_forward",
        action_params={
            "port": SWITCH_TO_SWITCH_PORT
        })
    ingress_sw.WriteTableEntry(table_entry)
    print ("Installed transit tunnel rule on %s" % ingress_sw.name)

    # 3) Tunnel Egress Rule
    # For our simple topology, the host will always be located on the
    # SWITCH_TO_HOST_PORT (port 1).
    # In general, you will need to keep track of which port the host is
    # connected to.
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.myTunnel_exact",
        match_fields={
            "hdr.myTunnel.dst_id": tunnel_id
        },
        action_name="MyIngress.myTunnel_egress",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": SWITCH_TO_HOST_PORT
        })
    egress_sw.WriteTableEntry(table_entry)
    print ("Installed egress tunnel rule on %s" % egress_sw.name)


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print ('\n----- Reading tables rules for %s -----' % sw.name)
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print ('%s: ' % table_name,)
            for m in entry.match:
                print (p4info_helper.get_match_field_name(table_name, m.field_id),)
                print ('%r' % (p4info_helper.get_match_field_value(m),),)
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print ('->', action_name,)
            for p in action.params:
                print (p4info_helper.get_action_param_name(action_name, p.param_id),)
                print ('%r' % p.value,)
            print()

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print ("%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            ))

def writePOutRule(p4info_helper, ingress_sw, padding, sw_addr):
    if padding == 0: # send to another switch
        table_entry = p4info_helper.buildTableEntry(
            table_name = "MyIngress.pkt_out_table",
            match_fields = {
                "hdr.packet_out.padding": padding
            },
            action_name = "MyIngress.lldp_forward",
            action_params={
                "swAddr": sw_addr
            })
        ingress_sw.WriteTableEntry(table_entry)
    elif padding == 1: # send back to controller
        table_entry = p4info_helper.buildTableEntry(
            table_name = "MyIngress.pkt_out_table",
            match_fields = {
                "hdr.packet_out.padding": padding
            },
            action_name = "MyIngress.response_to_cpu",
            action_params={
                "swAddr": sw_addr
            })
        ingress_sw.WriteTableEntry(table_entry)


def printGrpcError(e):
    print ("gRPC Error:", e.details(),)
    status_code = e.code()
    print ("(%s)" % status_code.name,
    traceback = sys.exc_info()[2])
    print ("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    time=0
    try:
        standard_client, mc_client = runtime_CLI.thrift_connect(
            'localhost', 9090,
            runtime_CLI.RuntimeAPI.get_thrift_services(1)
        )
        runtime_CLI.load_json_config(standard_client, None)
        
        run=runtime_CLI.RuntimeAPI(1,standard_client,mc_client)
        run2=runtime_CLI.RuntimeAPI(2,standard_client,mc_client)


        run.do_register_write("limit 0 100")

        
            
        # Print the tunnel counters every 2 seconds
        while True:
            #run.do_register_write("packet_limit 0 2")
            #print(run.do_register_read("packet_limit 0"))

            #run.do_register_write("packet_limit 0 4")
            #print(run.do_register_read("packet_limit 0"))
            now=datetime.now()
            print(now.strftime("%H:%M:%S"))
            print("time slice packet accepted or dropped (5 seconds) : ")
            print("\ttotal packets dropped : ",end="")
            run.do_register_read("dropped 0")
            
            print("\tTCP packets : ",end="")
            run.do_register_read("syn_counter 0")
            print("\tUDP packets : ",end="")
            run.do_register_read("udp_counter 0")
            print("\tICMP packets: ",end="")
            run.do_register_read("icmp_counter 0")


            if(time%5==0):
                run.do_register_reset("syn_counter")
                run.do_register_reset("ack_counter")
                run.do_register_reset("udp_counter")
                run.do_register_reset("icmp_counter")
                run.do_register_reset("synack_counter")
                run.do_register_reset("dns_count")
                run.do_register_reset("dropped")

            print("\n")
            time+=5
            sleep(5)
          #  print ('\n----- Reading packet_limit -----')
            #printCounter(p4info_helper, s1, "MyIngress.ingressTunnelCounter", 100)
            #printCounter(p4info_helper, s2, "MyIngress.egressTunnelCounter", 100)
            #printCounter(p4info_helper, s2, "MyIngress.ingressTunnelCounter", 200)
            #printCounter(p4info_helper, s1, "MyIngress.egressTunnelCounter", 200)
            
            

    except KeyboardInterrupt:
        print (" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/firewall.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/firewall.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print ("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print ("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
