"""FatTree topology by Howar31

Configurable K-ary FatTree topology
Only edit K should work

OVS Bridge with Spanning Tree Protocol

Note: STP bridges don't start forwarding until
after STP has converged, which can take a while!
See below for a command to wait until STP is up.

sudo mn --custom ~/mininet/custom/topo-fat-tree.py --topo fattree

Pass '--topo=fattree' from the command line
"""

from mininet.topo import Topo
 
class FatTree( Topo ):

    def __init__( self ):

        # Topology settings
        K = 4                           # K-ary FatTree
        podNum = K                      # Pod number in FatTree
        coreSwitchNum = pow((K/2),2)    # Core switches 
        aggrSwitchNum = ((K/2)*K)       # Aggregation switches
        edgeSwitchNum = ((K/2)*K)       # Edge switches
        hostNum = (K*pow((K/2),2))      # Hosts in K-ary FatTree
        dpid = 0
        hostId = 0

        # Initialize topology
        Topo.__init__( self )

        coreSwitches = []
        aggrSwitches = []
        edgeSwitches = []

        # Core
        for core in range(0, coreSwitchNum):
            dpid += 1
            coreSwitches.append(self.addSwitch("s"+str(dpid)))
        # Pod
        for pod in range(0, podNum):
        # Aggregate
            for aggr in range(0, aggrSwitchNum/podNum):
                dpid += 1
                aggrThis = self.addSwitch("s"+str(dpid))
                aggrSwitches.append(aggrThis)
                for x in range((K/2)*aggr, (K/2)*(aggr+1)):
#                    self.addLink(aggrSwitches[aggr+(aggrSwitchNum/podNum*pod)], coreSwitches[x])
                    self.addLink(aggrThis, coreSwitches[x])
        # Edge
            for edge in range(0, edgeSwitchNum/podNum):
                dpid += 1
                edgeThis = self.addSwitch("s"+str(dpid))
                edgeSwitches.append(edgeThis)
                for x in range((edgeSwitchNum/podNum)*pod, ((edgeSwitchNum/podNum)*(pod+1))):
                    self.addLink(edgeThis, aggrSwitches[x])
        # Host
                for x in range(0, (hostNum/podNum/(edgeSwitchNum/podNum))):
                    hostId += 1
                    self.addLink(edgeThis, self.addHost("h"+str(hostId)))
                    # self.addLink(edgeThis, self.addHost("h_"+str(pod)+"_"+str(edge)+"_"+str(x)))

topos = { 'fattree': ( lambda: FatTree() ) }
