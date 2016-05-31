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

import socket
from ookm.base.event import *
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import icmpv6
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6

_ETH_TYPE_IPV4 = 0x800
_ETH_TYPE_IPV6 = 0x86dd


# Helper
# use brute force to get every field from the msg and add to OFPMatch
def get_exact_match(msg):
    parser = msg.datapath.ofproto_parser
    pkt = packet.Packet(data=msg.data)
    pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
    if not pkt_ethernet:
        return None
    pkt_arp = pkt.get_protocol(arp.arp)
    pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
    pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
    pkt_icmp = pkt.get_protocol(icmp.icmp)
    pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
    pkt_tcp = pkt.get_protocol(tcp.tcp)
    pkt_udp = pkt.get_protocol(udp.udp)
    # TODO a lot of work...
    if pkt_ipv4:
        if pkt_tcp:
            return parser.OFPMatch(ip_proto=socket.IPPROTO_TCP, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst,
                                   tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port, eth_type=_ETH_TYPE_IPV4)
        if pkt_udp:
            return parser.OFPMatch(ip_proto=socket.IPPROTO_UDP, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst,
                                   udp_src=pkt_udp.src_port, udp_dst=pkt_udp.dst_port, eth_type=_ETH_TYPE_IPV4)
        if pkt_icmp:
            return parser.OFPMatch(ip_proto=socket.IPPROTO_ICMP, ipv4_src=pkt_ipv4.src, ipv4_dst=pkt_ipv4.dst,
                                   icmp_type=pkt_icmp.type, icmp_code=pkt_icmp.code, eth_type=_ETH_TYPE_IPV4)
    elif pkt_ipv6:
        if pkt_tcp:
            return parser.OFPMatch(ip_proto=socket.IPPROTO_TCP, ipv6_src=pkt_ipv6.src, ipv6_dst=pkt_ipv6.dst,
                                   tcp_src=pkt_tcp.src_port, tcp_dst=pkt_tcp.dst_port, eth_type=_ETH_TYPE_IPV6)
        if pkt_udp:
            return parser.OFPMatch(ip_proto=socket.IPPROTO_UDP, ipv6_src=pkt_ipv6.src, ipv6_dst=pkt_ipv6.dst,
                                   udp_src=pkt_udp.src_port, udp_dst=pkt_udp.dst_port, eth_type=_ETH_TYPE_IPV6)
        elif pkt_icmpv6:
            return parser.OFPMatch(ip_proto=socket.IPPROTO_ICMPV6, ipv6_src=pkt_ipv6.src, ipv6_dst=pkt_ipv6.dst,
                                   icmpv6_type_=pkt_icmpv6.type_, icmpv6_code=pkt_icmpv6.code, eth_type=_ETH_TYPE_IPV6)
    elif pkt_arp:
        # ("ARP EXACT MATCH NOT IMPLEMENTED YET")
        return None


class OokmFlowModContext(object):
    def __init__(self, ev):
        self.event = ev
        self._kv_dict = {}
        self._exact_match = False
        self._applied_forward = False
        self._forward_outport = None
        self._forward_buffer = None

    def set_field(self, kv_dict):
        for key in kv_dict:
            self._kv_dict[key] = kv_dict[key]

    def forward(self, outport, buffer=None):
        # ignore more than one forward
        if self._applied_forward:
            return

        self._applied_forward = True

        self._forward_outport = outport
        self._forward_buffer = buffer

    def forward_for_each(self, outport, buffer=None):
        # ignore more than one forward
        if self._applied_forward:
            return

        self._applied_forward = True
        self._exact_match = True

        self._forward_outport = outport
        self._forward_buffer = buffer

    def perform(self, matched_fields):
        if not isinstance(self.event, PacketIn):
            return
        if not (self._kv_dict or self._applied_forward):
            return

        msg = self.event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        actions = []
        # construct OFPActionSetField
        if self._kv_dict:
            actions.append(parser.OFPActionSetField(**self._kv_dict))
        # add forward action to the end of action list
        if self._applied_forward:
            if self._forward_buffer:
                actions.append(parser.OFPActionOutput(self._forward_outport, self._forward_buffer))
            else:
                actions.append(parser.OFPActionOutput(self._forward_outport))
        # construct match according to self._exact_match and determine priority
        if self._exact_match:
            match = get_exact_match(msg)
            priority = 2
        else:
            match = parser.OFPMatch(**matched_fields)
            priority = 1

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=msg.buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
            out = parser.OFPPacketOut(datapath=datapath, buffer_id = msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
