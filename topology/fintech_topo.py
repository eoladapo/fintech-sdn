"""
FinTech Enterprise Network Topology (Mininet)
- Critical Zone: Core Banking Server, Payment Gateway
- Access Zone: Branch Office, ATM Terminal, Clinet Host
- Adversarial Zone: Attacker Host
- Core/Aggregation Fabric: 3 Open vSwitch node running OpenFlow 1.3
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class FinTechTopology(Topo):
    def build(self):
        # 1. OpenFlow Switches (DPIDs assigned explicitly for predictable Ryu routing)
        s1 = self.addSwitch('s1', dpid='0000000000000001', protocols='OpenFlow13') # Core Switch
        s2 = self.addSwitch('s2', dpid='0000000000000002', protocols='OpenFlow13') # Payment Aggregation
        s3 = self.addSwitch('s3', dpid='0000000000000003', protocols='OpenFlow13') # Edge/Access Aggregation

        # 2. Critical Infrastructure Hosts
        bank_server = self.addHost('h_bank', ip='10.0.0.10/24', mac='00:00:00:00:00:10')
        payment_gatway = self.addHost('h_pay', ip='10.0.0.20/24', mac='00:00:00:00:00:20')

        # 3. Access Zone Hosts
        branch = self.addHost('h_br1', ip='10.0.0.30/24', mac='00:00:00:00:00:30')
        atm = self.addHost('h_atm', ip='10.0.0.40/24', mac='00:00:00:00:00:40')
        client = self.addHost('h_cli', ip='10.0.0.50/24', mac='00:00:00:00:00:50')

        # 4. Adversarial Host
        attacker = self.addHost('h_atk', ip='10.0.0.99/24', mac='00:00:00:00:00:99')

        # 5. Core Inter-Switch Mesh (provides multi-path routing options for optimization)
        # s1 <-> s2: Primary high-capacity core link
        self.addLink(s1, s2,cls=TCLink, bw=100, delay='2ms', loss=0)
        # s1 <-> s3: Primary branch-to-core backbone link
        self.addLink(s1, s3, cls=TCLink, bw=100, delay='2ms', loss=0)
        # s2 <-> s3: Redundant secondary link (higher latency / backup)
        self.addLink(s2, s3, cls=TCLink, bw=50, delay='8ms', loss=0)

        # 6. Host-to-Switch Access Access Links
        self.addLink(bank_server, s1, cls=TCLink, bw=100)
        self.addLink(payment_gatway, s2, cls=TCLink, bw=100)
        self.addLink(branch, s3, cls=TCLink, bw=20)
        self.addLink(atm, s3, cls=TCLink, bw=10)
        self.addLink(client, s3, cls=TCLink, bw=20)
        self.addLink(attacker, s3, cls=TCLink, bw=100)

topos = {'fintech_topology': (lambda: FinTechTopology())}


def run():
    setLogLevel('info')
    topo = FinTechTopology()


    # Initialiize Mininet using Open vSwitch and TCLink for realistic bandwidth/latency
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        link=TCLink,
        controller=None,
        autoSetMacs=False,
        autoStaticArp=False
    )

    info('*** Connecting to Remote Ryu Controller at 127.0.0.1:6653\n')
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Starting Network\n')
    net.start()

    info('*** Topology ready. Entering Mininet CLI.\n')
    CLI(net)

    info('*** Stopping Network\n')
    net.stop()

if __name__ == '__main__':
    run()