#!/usr/bin/env python3
"""
Intelligent FinTech SDN Controller with ML-Driven DDoS Mitigation
- Dynamic Dijkstra Shortest-Path Forwarding (OpenFlow 1.3)
- Built-in ARP Proxy with static pre-population to prevent loops & cold-start drops
- Real-time Flow Telemetry Monitoring & Scikit-Learn Inference
- Automated OpenFlow Drop Rule Insertion on Confirmed Attackers
"""

import eventlet
eventlet.monkey_patch()

import os
import joblib
import pandas as pd
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx

MODEL_PATH = os.path.expanduser('~/fintech-sdn/models/ddos_rf_model.pkl')

class FinTechMitigationController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FinTechMitigationController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.datapaths = {}
        self.mac_to_port = {}
        self.blocked_ports = set()

        # Pre-populate static ARP bindings from fintech_topo.py to eliminate ARP storms & cold-starts
        self.arp_table = {
            '10.0.0.10': '00:00:00:00:00:10',  # h_bank
            '10.0.0.20': '00:00:00:00:00:20',  # h_pay
            '10.0.0.30': '00:00:00:00:00:30',  # h_br1
            '10.0.0.40': '00:00:00:00:00:40',  # h_atm
            '10.0.0.50': '00:00:00:00:00:50',  # h_cli
            '10.0.0.99': '00:00:00:00:00:99'   # h_atk
        }

        # Load trained Random Forest model
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.logger.info(f"[+] Loaded ML Anomaly Model from {MODEL_PATH}")
        else:
            self.logger.error(f"[-] Model not found at {MODEL_PATH}!")
            self.model = None

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        # Default Table-Miss entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.info(f"[Core Fabric] DPID={datapath.id:016x} Active")

    @set_ev_cls(event.EventSwitchEnter)
    @set_ev_cls(event.EventLinkAdd)
    def _update_topology(self, ev):
        for s in get_switch(self.topology_api_app, None):
            self.net.add_node(s.dp.id)
        for link in get_link(self.topology_api_app, None):
            cost = 8 if {link.src.dpid, link.dst.dpid} == {2, 3} else 2
            self.net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no, weight=cost)
            self.net.add_edge(link.dst.dpid, link.src.dpid, port=link.dst.port_no, weight=cost)

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp))
            hub.sleep(2)


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        if not self.model:
            return

        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id

        for stat in body:
            # Skip default table-miss or empty rules
            if stat.priority <= 0 or stat.packet_count == 0:
                continue

            # Robust in_port extraction
            in_port = 0
            if 'in_port' in stat.match:
                in_port = stat.match['in_port']
            else:
                for field in stat.match.to_jsondict().get('OFPMatch', {}).get('oxm_fields', []):
                    tlv = field.get('OXMTlv', {})
                    if tlv.get('field') == 'in_port':
                        in_port = tlv.get('value', 0)
                        break

            # Never block inter-switch backbone links
            # s1 trunks: ports 2, 3; s2 trunks: ports 2, 3; s3 trunks: ports 1, 2
            trunk_ports = {
                1: [2, 3],
                2: [2, 3],
                3: [1, 2]
            }
            if in_port in trunk_ports.get(dpid, []):
                continue

            if (dpid, in_port) in self.blocked_ports or in_port == 0:
                continue

            pkt_cnt = stat.packet_count
            byte_cnt = stat.byte_count
            dur = max(stat.duration_sec, 1)
            pkt_rate = pkt_cnt / dur
            byte_rate = byte_cnt / dur
            bytes_per_pkt = byte_cnt / pkt_cnt if pkt_cnt else 0

            # Guard: ONLY run ML inference on anomalous flows (rate > 50 pkts/s and > 100 packets)
            if pkt_rate > 50 and pkt_cnt > 100:
                features = pd.DataFrame([[pkt_cnt, byte_cnt, dur, pkt_rate, byte_rate, bytes_per_pkt]],
                                        columns=['packet_count', 'byte_count', 'duration_sec',
                                                 'packet_rate', 'byte_rate', 'bytes_per_packet'])

                prediction = self.model.predict(features)[0]

                if prediction == 1 or pkt_rate > 200:
                    self.logger.warning(
                        f"\n[ALERT: DDoS INTRUSION DETECTED] Switch={dpid}, Edge Ingress Port={in_port} | "
                        f"Pkt Rate={pkt_rate:.1f} pkts/s, Total Packets={pkt_cnt}"
                    )
                    self._apply_mitigation(datapath, in_port)

    def _apply_mitigation(self, datapath, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Push DROP rule with highest priority (100)
        match = parser.OFPMatch(in_port=in_port)
        inst = []  # Empty action list = drop
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=inst,
            idle_timeout=120,
            hard_timeout=300
        )
        datapath.send_msg(mod)
        self.blocked_ports.add((datapath.id, in_port))
        self.logger.warning(f"[MITIGATION ACTIVE] Installed OpenFlow DROP rule on Switch={datapath.id} Port={in_port}\n")
   
    def _apply_mitigation(self, datapath, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Drop rule matching the offending switch ingress port
        match = parser.OFPMatch(in_port=in_port)
        inst = []  # Empty actions = DROP
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=inst,
            idle_timeout=120,
            hard_timeout=300
        )
        datapath.send_msg(mod)
        self.blocked_ports.add((datapath.id, in_port))
        self.logger.warning(f"[MITIGATION ACTIVE] Installed OpenFlow DROP rule on Switch={datapath.id} Port={in_port}\n")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        if (dpid, in_port) in self.blocked_ports:
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        self.mac_to_port[dpid][src] = in_port

        # Host discovery in Dijkstra network graph
        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port, weight=0)
            self.net.add_edge(src, dpid, weight=0)

        # ARP Proxy: reply to requests immediately using known ARP mappings
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src
            if arp_pkt.opcode == arp.ARP_REQUEST:
                resolved_mac = self.arp_table.get(arp_pkt.dst_ip)
                if resolved_mac:
                    reply_pkt = packet.Packet()
                    reply_pkt.add_protocol(ethernet.ethernet(
                        dst=src, src=resolved_mac, ethertype=ether_types.ETH_TYPE_ARP
                    ))
                    reply_pkt.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=resolved_mac,
                        src_ip=arp_pkt.dst_ip,
                        dst_mac=src,
                        dst_ip=arp_pkt.src_ip
                    ))
                    reply_pkt.serialize()
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=[parser.OFPActionOutput(in_port)],
                        data=reply_pkt.data
                    )
                    datapath.send_msg(out)
                    return

        # Dijkstra least-cost routing
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
            mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match,
                                    instructions=inst, idle_timeout=60)
            datapath.send_msg(mod)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)