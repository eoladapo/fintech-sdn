#!/usr/bin/env python3
"""
Telemetry & Flow Data Collector Controller
Logs OpenFlow statistics (packet count, byte count, duration, rate, ratio)
with binary label: 0 for Benign, 1 for Malicious/DDoS.
"""

import eventlet
eventlet.monkey_patch()

import os
import csv
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx

DATASET_PATH = os.path.expanduser('~/fintech-sdn/data/flow_dataset.csv')

class DataCollectorController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DataCollectorController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.datapaths = {}
        self.arp_table = {}
        self.mac_to_port = {}
        
        # Initialize CSV
        os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
        if not os.path.exists(DATASET_PATH) or os.path.getsize(DATASET_PATH) == 0:
            with open(DATASET_PATH, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'dpid', 'in_port', 'packet_count', 'byte_count', 
                    'duration_sec', 'packet_rate', 'byte_rate', 
                    'bytes_per_packet', 'label'
                ])

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"[Collector Attached] DPID={datapath.id}")

    @set_ev_cls(event.EventSwitchEnter)
    @set_ev_cls(event.EventLinkAdd)
    def _update_topo(self, ev):
        for s in get_switch(self.topology_api_app, None):
            self.net.add_node(s.dp.id)
        for link in get_link(self.topology_api_app, None):
            weight = 8 if {link.src.dpid, link.dst.dpid} == {2, 3} else 2
            self.net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no, weight=weight)
            self.net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no, weight=weight)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                req = parser.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(2)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        rows_to_write = []
        for stat in body:
            if stat.priority <= 0 or stat.packet_count == 0:
                continue

            match_fields = stat.match.to_jsondict().get('OFPMatch', {}).get('oxm_fields', [])
            in_port = 0
            for field in match_fields:
                if field.get('OXMTlv', {}).get('field') == 'in_port':
                    in_port = field['OXMTlv']['value']
                    break

            pkt_cnt = stat.packet_count
            byte_cnt = stat.byte_count
            dur = max(stat.duration_sec, 1)

            pkt_rate = pkt_cnt / dur
            byte_rate = byte_cnt / dur
            bytes_per_pkt = byte_cnt / pkt_cnt if pkt_cnt else 0

            # Attacker h_atk connects to switch s3 (dpid 3) on port 6
            # Label = 1 (DDoS) for port 6 on switch 3 or volumetric flood spikes
            label = 1 if (dpid == 3 and in_port == 6) or pkt_rate > 500 else 0

            rows_to_write.append([
                dpid, in_port, pkt_cnt, byte_cnt,
                dur, round(pkt_rate, 2), round(byte_rate, 2),
                round(bytes_per_pkt, 2), label
            ])

        if rows_to_write:
            with open(DATASET_PATH, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(rows_to_write)
                f.flush()
            self.logger.info(f"[Logged] {len(rows_to_write)} flow records to CSV.")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst, src, dpid = eth.dst, eth.src, datapath.id
        self.mac_to_port[dpid][src] = in_port

        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port, weight=0)
            self.net.add_edge(src, dpid, weight=0)

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src

        if dst in self.net:
            try:
                path = nx.shortest_path(self.net, src, dst, weight='weight')
            except nx.NetworkXNoPath:
                return

            if dpid in path:
                out_port = self.net[dpid][path[path.index(dpid) + 1]]['port']
            else:
                out_port = ofproto.OFPP_FLOOD
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            # 60s idle timeout so active flows stick around for collector polling
            mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match,
                                    instructions=inst, idle_timeout=60)
            datapath.send_msg(mod)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)