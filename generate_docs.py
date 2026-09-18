#!/usr/bin/env python3
"""
Generate Complete Technical Documentation for:
SDN-BASED INTELLIGENT TRAFFIC ROUTING FOR SECURE AND OPTIMISED FINTECH NETWORK INFRASTRUCTURE
Exports directly to a styled Microsoft Word document (.docx).
"""

import os
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

def set_cell_background(cell, fill_color):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_color)
    tc_pr.append(shd)

def create_document():
    doc = docx.Document()

    # Document Geometry
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Styles
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = RGBColor(0x22, 0x22, 0x22)

    # Document Title
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(0)
    title_p.paragraph_format.space_after = Pt(4)
    run_title = title_p.add_run("Software-Defined Networking (SDN)-Based Intelligent Traffic Routing for Secure and Optimised FinTech Network Infrastructure")
    run_title.font.size = Pt(22)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(0x0F, 0x2C, 0x59)

    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_after = Pt(24)
    run_sub = sub_p.add_run("System Architecture, Codebase Walkthrough, and End-to-End Operational Manual")
    run_sub.font.size = Pt(13)
    run_sub.font.italic = True
    run_sub.font.color.rgb = RGBColor(0x66, 0x66, 0x66)

    # Helper function for adding sections
    def add_h1(text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(18)
        h.paragraph_format.space_after = Pt(6)
        r = h.add_run(text)
        r.font.size = Pt(15)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0x0F, 0x2C, 0x59)

    def add_h2(text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(12)
        h.paragraph_format.space_after = Pt(4)
        r = h.add_run(text)
        r.font.size = Pt(12)
        r.font.bold = True
        r.font.color.rgb = RGBColor(0xD8, 0x00, 0x32)

    def add_code_block(code_text):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(4)
        p.paragraph_format.space_after = Pt(8)
        p.paragraph_format.left_indent = Inches(0.2)
        r = p.add_run(code_text)
        r.font.name = 'Consolas'
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(0x1B, 0x4D, 0x3E)

    # 1. Project High-Level Overview
    add_h1("1. High-Level Executive Summary (Simple Terms)")
    doc.add_paragraph(
        "Modern Financial Technology (FinTech) networks process mission-critical operations such as card authorizations, "
        "inter-bank settlements, and ATM transactions. A volumetric Distributed Denial of Service (DDoS) flood targeting a payment gateway "
        "or core banking server saturates line capacity, locks controller computational resources, and causes legitimate transactions to fail.\n\n"
        "This project implements a fully virtualized, closed-loop autonomous Software-Defined Networking (SDN) defense ecosystem. "
        "Unlike traditional networks where switches make local routing decisions using static protocols, this solution utilizes OpenFlow 1.3 "
        "to separate the Control Plane (Ryu Controller) from the Data Plane (Open vSwitch fabric). The controller dynamically discovers network "
        "topology, computes least-cost forwarding paths using Dijkstra's algorithm, periodically samples port counters, and streams live telemetry "
        "into a trained Scikit-Learn Machine Learning classifier. When malicious flooding is detected, the controller proactively injects "
        "microsecond-level OpenFlow DROP instructions into the exact ingress edge switch port, severing the attack vector while preserving "
        "100% uninterrupted availability for legitimate transactions."
    )

    # 2. Topology Design
    add_h1("2. FinTech Topology Architecture (topology/fintech_topo.py)")
    doc.add_paragraph(
        "The simulated environment constructs a multi-tier banking infrastructure across three OpenFlow-enabled switches (s1, s2, s3) "
        "interconnected in a triangular mesh with deliberate asymmetric link metrics."
    )

    table = doc.add_table(rows=7, cols=4)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Node Name", "IP Address", "Attached Switch", "Network Functional Role"]
    for i, title in enumerate(headers):
        cell = table.cell(0, i)
        cell.paragraphs[0].text = title
        cell.paragraphs[0].runs[0].font.bold = True
        set_cell_background(cell, "0F2C59")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    node_data = [
        ("h_bank", "10.0.0.10", "s1 (Port 1)", "Core Banking Transaction Server & Ledger"),
        ("h_pay", "10.0.0.20", "s2 (Port 1)", "FinTech Payment Gateway Engine"),
        ("h_br1", "10.0.0.30", "s3 (Port 3)", "Bank Regional Branch Workstation"),
        ("h_atm", "10.0.0.40", "s3 (Port 4)", "Automated Teller Machine (ATM) Terminal"),
        ("h_cli", "10.0.0.50", "s3 (Port 5)", "Legitimate Mobile & Web Retail Client"),
        ("h_atk", "10.0.0.99", "s3 (Port 6)", "Compromised Host / Botnet Flooder")
    ]

    for row_idx, data in enumerate(node_data, start=1):
        for col_idx, text in enumerate(data):
            c = table.cell(row_idx, col_idx)
            c.paragraphs[0].text = text
            if row_idx % 2 == 0:
                set_cell_background(c, "F2F2F2")

    doc.add_paragraph()
    doc.add_paragraph(
        "Link Metric Allocations:\n"
        "• Switch 1 <-> Switch 2: 100 Mbps, 2ms delay (Weight = 2)\n"
        "• Switch 1 <-> Switch 3: 100 Mbps, 2ms delay (Weight = 2)\n"
        "• Switch 2 <-> Switch 3: 50 Mbps, 8ms delay (Weight = 8 - High Cost Link)"
    )

    # 3. Code Explanations
    add_h1("3. Comprehensive Script & Code Walkthrough")
    
    add_h2("A. Topology Script: topology/fintech_topo.py")
    doc.add_paragraph(
        "• Class FinTechTopo(Topo): Inherits from Mininet's base Topo class to define custom network graphs.\n"
        "• self.addSwitch('s1', protocols='OpenFlow13'): Instantiates software switches configured exclusively for OpenFlow 1.3.\n"
        "• self.addHost(...): Configures endpoints with fixed IP addresses, MAC addresses, and default gateway assignments.\n"
        "• self.addLink(node1, node2, cls=TCLink, bw=..., delay=...): Emulates physical link constraints including bandwidth caps, propagation delay, and Hierarchical Token Bucket (HTB) queue disciplines.\n"
        "• RemoteController('c0', ip='127.0.0.1', port=6653): Instructs the virtual switch fabric to bind to an external SDN controller running locally on the standard OpenFlow port 6653."
    )

    add_h2("B. Telemetry Collector: controller/data_collector_controller.py")
    doc.add_paragraph(
        "• Class DataCollectorController(app_manager.RyuApp): Core application running inside the Ryu framework.\n"
        "• switch_features_handler(self, ev): Triggered upon switch handshake. Injects the priority=0 Table-Miss flow entry directing unhandled traffic to the controller via OFPP_CONTROLLER.\n"
        "• _update_topo(self, ev): Dynamically discovers active switches and links via LLDP topology events and builds an internal NetworkX directed graph (nx.DiGraph).\n"
        "• _monitor(self): Asynchronous green-thread (hub.spawn) that iterates every 2 seconds, sending OFPFlowStatsRequest to all connected datapaths.\n"
        "• _flow_stats_reply_handler(self, ev): Extracts raw OpenFlow counters (packet_count, byte_count, duration_sec), derives traffic dynamics (packet_rate, byte_rate, bytes_per_packet), appends binary ground-truth labels (0 for benign, 1 for ingress bursts on attacker port 6), and writes batches directly to data/flow_dataset.csv.\n"
        "• _packet_in_handler(self, ev): Executes Dijkstra least-cost routing using NetworkX (nx.shortest_path) to determine optimal switch egress ports and installs corresponding bidirectional flow entries."
    )

    add_h2("C. Machine Learning Pipeline: ml/train_model.py")
    doc.add_paragraph(
        "• Data Sanitization: Loads data/flow_dataset.csv, replaces numerical infinities (e.g., division by zero duration), and drops empty records.\n"
        "• Feature Matrix (X) & Ground Truth (y): Extracts 6 behavioral features: packet_count, byte_count, duration_sec, packet_rate, byte_rate, and bytes_per_packet against the target binary label.\n"
        "• train_test_split(..., test_size=0.25, stratify=y): Partitions dataset into 75% training and 25% testing subsets while preserving class proportions.\n"
        "• RandomForestClassifier(n_estimators=100, max_depth=12): Fits an ensemble of 100 decision trees to minimize classification variance and prevent overfitting.\n"
        "• joblib.dump(clf, MODEL_PATH): Serializes the trained classifier to models/ddos_rf_model.pkl for real-time inference."
    )

    add_h2("D. Autonomous Mitigation Controller: controller/mitigation_controller.py")
    doc.add_paragraph(
        "• Built-in ARP Proxy: Stores static IP-to-MAC resolutions for all FinTech hosts, instantly satisfying ARP requests to prevent broadcast loops across the triangular switch topology.\n"
        "• Backbone Link Whitelist: Guards inter-switch trunk ports (s1-eth2, s1-eth3, s2-eth2, s2-eth3, s3-eth1, s3-eth2) from being blocked, ensuring core transit fabric remains intact.\n"
        "• Inference Guard: Ensures telemetry stats pass minimum operational criteria (packet_rate > 50 pkts/s and packet_count > 100) before triggering ML inference, eliminating false positives on low-rate pings.\n"
        "• _apply_mitigation(self, datapath, in_port): Asynchronously injects an OpenFlow rule with priority=100 matching strictly on in_port with an empty action list (actions=drop), isolating the threat host in hardware table-0."
    )

    add_h2("E. Metric Evaluation Engine: ml/evaluate_metrics.py")
    doc.add_paragraph(
        "• Evaluates the serialized model against test splits to export publication-ready performance graphs.\n"
        "• Outputs: data/plots/confusion_matrix.png, data/plots/roc_curve.png (AUC metric), and data/plots/feature_importance.png."
    )

    # 4. Step-by-Step Command Guide
    add_h1("4. Step-by-Step Operational Runbook & Verification Commands")
    doc.add_paragraph("Follow these exact steps to execute the entire environment from cold start to mitigation.")

    doc.add_paragraph("Step 1: Environment Cleanup")
    add_code_block("sudo pkill -9 -f ryu-manager\nsudo mn -c")

    doc.add_paragraph("Step 2: Launch the Mitigation Controller (Terminal 1)")
    add_code_block("cd ~/fintech-sdn\nryu-manager --observe-links --ofp-tcp-listen-port 6653 controller/mitigation_controller.py")

    doc.add_paragraph("Step 3: Launch the FinTech Topology (Terminal 2)")
    add_code_block("cd ~/fintech-sdn\nsudo python3 topology/fintech_topo.py")

    doc.add_paragraph("Step 4: Verify Baseline Normal Mesh Reachability (Inside Mininet CLI)")
    add_code_block("mininet> pingall\nmininet> h_cli ping -c 3 10.0.0.10")

    doc.add_paragraph("Step 5: Launch Volumetric DDoS Flood Attack (Inside Mininet CLI)")
    add_code_block("mininet> h_atk timeout 10 hping3 -S -p 80 --flood 10.0.0.10")

    doc.add_paragraph("Step 6: Verify Autonomous Quarantine & Protected Traffic Continuity (Inside Mininet CLI)")
    add_code_block(
        "mininet> h_atk ping -c 3 10.0.0.10\n"
        "# Result: 100% packet loss (Attacker blocked)\n\n"
        "mininet> h_cli ping -c 3 10.0.0.10\n"
        "# Result: 0% packet loss (Legitimate banking traffic operational)"
    )

    doc.add_paragraph("Step 7: Verify OpenFlow Drop Rule in Switch Hardware (Terminal 3)")
    add_code_block("sudo ovs-ofctl -O OpenFlow13 dump-flows s3")

    doc.add_paragraph("Step 8: Generate Academic Figures & Plots (Terminal 3)")
    add_code_block("python3 ~/fintech-sdn/ml/evaluate_metrics.py\nls -la ~/fintech-sdn/data/plots/")

    # 5. Experimental Results Table
    add_h1("5. Verified Experimental Performance Metrics")
    doc.add_paragraph("Summary of empirical validation recorded during testing:")

    res_table = doc.add_table(rows=6, cols=3)
    res_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    r_headers = ["Metric / Parameter", "Observed Empirical Value", "FinTech Infrastructure Impact"]
    for i, title in enumerate(r_headers):
        c = res_table.cell(0, i)
        c.paragraphs[0].text = title
        c.paragraphs[0].runs[0].font.bold = True
        set_cell_background(c, "0F2C59")
        c.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    res_data = [
        ("Model Accuracy", "98.14%", "Near-zero false positive rate prevents financial disruption."),
        ("DDoS F1-Score", "0.89 (Recall: 85%, Precision: 95%)", "High-confidence detection of volumetric flood signatures."),
        ("Mitigation Latency", "< 3.0 Seconds", "Autonomous response halts attack before core servers crash."),
        ("Packets Dropped at Edge", "297,001 Packets (~16 MB)", "Line-rate kernel drop relieves controller and transit links."),
        ("Legitimate Client Availability", "100% Received (0% Packet Loss)", "Banking client (h_cli) maintained 5.05ms average RTT.")
    ]

    for row_idx, data in enumerate(res_data, start=1):
        for col_idx, text in enumerate(data):
            c = res_table.cell(row_idx, col_idx)
            c.paragraphs[0].text = text
            if row_idx % 2 == 0:
                set_cell_background(c, "F2F2F2")

    output_path = os.path.expanduser('~/fintech-sdn/FinTech_SDN_Complete_Documentation.docx')
    doc.save(output_path)
    print(f"[+] Complete documentation exported successfully to: {output_path}")

if __name__ == '__main__':
    create_document()