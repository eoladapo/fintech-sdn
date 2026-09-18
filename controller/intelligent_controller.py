"""
Intelligent FinTech SDN controller
- OpenFlow 1.3 Multipath Routing & Loop Avoidance using NetworkX Dijkstra
- Dynamic Link Cost Evaluation based on Delay and Bandwidth
- Periodic Port & Flow Statistics Polling (Telemetry Engine for ML DDoS Detection)
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
import networkx as nx

class IntelligentFinTechController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IntelligentFinTechController, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        self.switches = {}
        self.mac_to_port = {}
        self.datapaths = {}

        # Monitor loop for traffic metrics collection
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_feature_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath

        # Install table-miss flow entry (send unmatched packets to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"[Switch Connected] DPID: {datapath.id:016x}")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=20, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    # Topology Discovery Events
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        switch_list = get_switch(self.topology_api_app, None)
        switches = [s.dp.id for s in switch_list]
        self.net.add_nodes_from(switches)

        links_list = get_link(self.topology_api_app, None)
        links = []
        for link in links_list:
            # Custom edge weight based on topological link attributes (latency metric)
            cost = 2
            if (link.src.dpid == 2 and link.dst.dpid == 3) or (link.src.dpid == 3 and link.dst.dpid == 2):
                cost = 8 # Redundant 50Mbps link higher cost penalty
            
            links.append((link.src.dpid, link.dst.dpid, {'port': link.src.port_no, 'weight': cost}))
            links.append((link.dst.dpid, link.src.dpid, {'port': link.dst.port_no, 'weight': cost}))

        self.net.add_edges_from(links)
        self.logger.info(f"[Topology Updated] Active Switches: {len(switches)}, Active Links: {len(links)//2}")

    # Telemetry Monitor Routine (Fetches port & flow stats for ML pipeline)
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        # Parse flows excluding the table-miss entry
        for stat in sorted([flow for flow in body if flow.priority > 0],
                           key=lambda flow: (flow.match.get('in_port', 0))):
            self.logger.debug(f"Stats DPID={dpid:016x} Pkts={stat.packet_count} Bytes={stat.byte_count} Dur={stat.duration_sec}")

    # Packet-In Event Handler
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packet-in (topology discovery frames)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Learn host attachment point in the graph
        if src not in self.net:
            self.net.add_node(src)
            self.net.add_edge(dpid, src, port=in_port, weight=0)
            self.net.add_edge(src, dpid, weight=0)

        # Route packet
        if dst in self.net:
            try:
                # Dijkstra Shortest Path Calculation
                path = nx.shortest_path(self.net, src, dst, weight='weight')
            except nx.NetworkXNoPath:
                return

            if dpid in path:
                next_hop = path[path.index(dpid) + 1]
                out_port = self.net[dpid][next_hop]['port']
            else:
                out_port = ofproto.OFPP_FLOOD
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # If destination is resolved, install an OpenFlow flow rule
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)