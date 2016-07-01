# Copyright 2016 Sheng Wang <kikyouer at gmail com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ookm.framework.ryulib import *
import networkx


def setup_virtual_controller(vip):
    DstIp(vip) >> [ApplyController()]


class ShortestPathForwarding(Selector):
    def select(self, event):
        if not isinstance(event, PacketIn):
            return []
        # extract dst host's mac
        msg = event.msg
        src = msg.datapath.id
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if pkt_ethernet:
            pkt_lldp = pkt.get_protocol(lldp.lldp)
            if pkt_lldp:
                return []
            else:
                dst_mac = pkt_ethernet.dst
        else:
            return []

        # find the switch connecting dst host
        r = host_mgr.query_host(mac=dst_mac)
        if r:
            last_switch_dpid, _ = r
        else:
            return []

        # find links to the last switch
        path = networkx.shortest_path(link_mgr.topology, src, last_switch_dpid)
        dpid_pairs = [(path[i], path[i+1]) for i in range(len(path) - 1)]
        generated_path = []
        for (src_dpid, dst_dpid) in dpid_pairs:
            generated_path.append(Link(switch_switch=(FromSwitch(src_dpid), FromSwitch(dst_dpid))))

        # add the switch-to-host link
        generated_path.append(Link(switch_host=(FromSwitch(last_switch_dpid), Host(mac=dst_mac))))

        return [generated_path]


'''
class DijkstraOnLinkLoadToDstHost(Selector):
    def select(self, event):
        if not isinstance(event, PacketIn):
            return []
        # extract dst IP
        msg = event.msg
        src = msg.datapath.id
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if pkt_ethernet:
            dst_mac = pkt_ethernet.dst
        else:
            return []

        # find the switch connecting dst host
        r = host_mgr.query_host(mac=dst_mac)
        if r:
            last_switch_dpid, _ = r
        else:
            return []

        # find links to the last switch
        path = networkx.shortest_path(link_mgr.topology, src, last_switch_dpid)
        dpid_pairs = [(path[i], path[i+1]) for i in range(len(path) - 1)]
        generated_path = []
        for (src_dpid, dst_dpid) in dpid_pairs:
            generated_path.append(Link(switch_switch=(FromSwitch(src_dpid), FromSwitch(dst_dpid))))

        # add the switch-to-host link
        generated_path.append(Link(switch_host=(FromSwitch(last_switch_dpid), Host(mac=dst_mac))))
        return [generated_path]
'''
