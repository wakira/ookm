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

import random

from ryu.ofproto import ofproto_v1_3
from ryu.controller import ofp_event
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import icmpv6
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import lldp
import socket
from ookm.base.nal_interface import *
from ookm.base.event import *
from ookm.framework.core import ookm_log, host_mgr, link_mgr
from ookm.lang.action import Action
from ookm.lang.predicate import AtomicPredicate
from ookm.lang.predicate import predicate_conflict_helper
from ookm.lang.rule import Rule
from ookm.lang.selector import *

# Predicates


class Anything(AtomicPredicate):
    def _test(self, event):
        return True


class IsErrorIn(AtomicPredicate):
    def _test(self, event):
        return isinstance(event, ofp_event.EventOFPErrorMsg)


class IsPacketIn(AtomicPredicate):
    def _test(self, event):
        return isinstance(event, ofp_event.EventOFPPacketIn)


class IsPortStatsReceived(AtomicPredicate):
    def _test(self, event):
        return isinstance(event, ofp_event.EventOFPPortStatus)


class IsControlMessages(AtomicPredicate):
    def _test(self, event):
        if not isinstance(event, PacketIn):
            return
        msg = event.msg
        pkt = packet.Packet(data=msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return None
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
        # pkt_lldp = pkt.get_protocol(lldp.lldp)
        return pkt_arp or pkt_icmp or pkt_icmpv6


class FromSwitch(AtomicPredicate):
    def __init__(self, dpid):
        super(FromSwitch, self).__init__()
        self.dpid = dpid

    def _test(self, event):
        return event.msg.datapath.id == self.dpid

    def conflicts_with(self, other):
        return predicate_conflict_helper(self, self.dpid, other, other.dpid)

    def __eq__(self, other):
        return super(FromSwitch, self).__eq__(other) and self.dpid == other.dpid


class IsICMP(AtomicPredicate):
    def _test(self, event):
        if not isinstance(event, PacketIn):
            return False
        raw = event.msg.data
        pkt = packet.Packet(data=raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
        return pkt_icmp or pkt_icmpv6


class InPort(AtomicPredicate):
    def __init__(self, port):
        super(InPort, self).__init__()
        self.port = port
        self.fields_filter = {'in_port': port}
        self.matched_fields = self.fields_filter

    def _test(self, event):
        if not isinstance(event, PacketIn):
            return False
        msg = event.msg
        port = msg.match['in_port']
        return port == self.port

    def conflicts_with(self, other):
        return predicate_conflict_helper(self, self.port, other, other.port)

    def __eq__(self, other):
        return super(InPort, self).__eq__(other) and self.port == other.port


class TcpSrcPort(AtomicPredicate):
    def __init__(self, port):
        super(TcpSrcPort, self).__init__()
        self.port = port
        # eth_type will be added to matched_fields in _test()
        self.fields_filter = {'tcp_src': self.port, 'ip_proto': socket.IPPROTO_TCP}
        self.matched_fields = self.fields_filter

    def _test(self, event):
        if not isinstance(event, PacketIn):
            return
        raw = event.msg.data
        pkt = packet.Packet(data=raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        if pkt_ipv4:
            self.matched_fields['eth_type'] = ETH_TYPE_IPV4
        elif pkt_ipv6:
            self.matched_fields['eth_type'] = ETH_TYPE_IPV6
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        return pkt_tcp and pkt_tcp.src_port == self.port

    def conflicts_with(self, other):
        return predicate_conflict_helper(self, self.port, other, other.port)

    def __eq__(self, other):
        return super(TcpSrcPort, self).__eq__(other) and self.port == other.port


class UdpSrcPort(AtomicPredicate):
    def __init__(self, port):
        super(UdpSrcPort, self).__init__()
        self.port = port
        # eth_type will be added to matched_fields in _test()
        self.fields_filter = {'udp_src': self.port, 'ip_proto': socket.IPPROTO_UDP}
        self.matched_fields = self.fields_filter

    def _test(self, event):
        if not isinstance(event, PacketIn):
            return
        raw = event.msg.data
        pkt = packet.Packet(data = raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        if pkt_ipv4:
            self.matched_fields['eth_type'] = ETH_TYPE_IPV4
        elif pkt_ipv6:
            self.matched_fields['eth_type'] = ETH_TYPE_IPV6
        return pkt_udp and pkt_udp.src_port == self.port

    def conflicts_with(self, other):
        return predicate_conflict_helper(self, self.port, other, other.port)

    def __eq__(self, other):
        return super(UdpSrcPort, self).__eq__(other) and self.port == other.port


class TcpDstPort(AtomicPredicate):
    def __init__(self, port):
        super(TcpDstPort, self).__init__()
        self.port = port
        # eth_type will be added to matched_fields in _test()
        self.fields_filter = {'tcp_dst': self.port, 'ip_proto': socket.IPPROTO_TCP}
        self.matched_fields = self.fields_filter

    def _test(self, event):
        if not isinstance(event, PacketIn):
            return
        raw = event.msg.data
        pkt = packet.Packet(data = raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        if pkt_ipv4:
            self.matched_fields['eth_type'] = ETH_TYPE_IPV4
        elif pkt_ipv6:
            self.matched_fields['eth_type'] = ETH_TYPE_IPV6
        return pkt_tcp and pkt_tcp.dst_port == self.port

    def conflicts_with(self, other):
        return predicate_conflict_helper(self, self.port, other, other.port)

    def __eq__(self, other):
        return super(TcpDstPort, self).__eq__(other) and self.port == other.port


class UdpDstPort(AtomicPredicate):
    def __init__(self, port):
        super(UdpDstPort, self).__init__()
        self.port = port
        self.fields_filter = {'udp_dst': self.port, 'ip_proto': socket.IPPROTO_UDP}
        self.matched_fields = self.fields_filter

    def _test(self, event):
        if not isinstance(event, PacketIn):
            return
        raw = event.msg.data
        pkt = packet.Packet(data = raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        if pkt_ipv4:
            self.matched_fields['eth_type'] = ETH_TYPE_IPV4
        elif pkt_ipv6:
            self.matched_fields['eth_type'] = ETH_TYPE_IPV6
        return pkt_udp and pkt_udp.dst_port == self.port

    def conflicts_with(self, other):
        return predicate_conflict_helper(self, self.port, other, other.port)

    def __eq__(self, other):
        return super(UdpDstPort, self).__eq__(other) and self.port == other.port


class SrcIp(AtomicPredicate):
    def __init__(self, ip_str):
        super(SrcIp, self).__init__()
        self.ip_str = ip_str
        self.ipv4 = ':' not in ip_str
        if self.ipv4:
            self.fields_filter = {'eth_type': ETH_TYPE_IPV4, 'ipv4_src': ip_str}
        else:
            self.fields_filter = {'eth_type': ETH_TYPE_IPV6, 'ipv6_src': ip_str}
        self.matched_fields = self.fields_filter

    def _test(self, event):
        if not isinstance(event, PacketIn):
            return
        raw = event.msg.data
        pkt = packet.Packet(data=raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self.matched_fields = {'eth_type': ETH_TYPE_ARP, 'arp_src_ip': self.ip_str}
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        return (self.ipv4 and pkt_arp and pkt_arp.src_ip == self.ip_str) or\
               (self.ipv4 and pkt_ipv4 and pkt_ipv4.src == self.ip_str) or\
               (not self.ipv4 and pkt_ipv6 and pkt_ipv6.src == self.ip_str)

    def conflicts_with(self, other):
        return predicate_conflict_helper(self, self.ip_str, other, other.ip_str)

    def __eq__(self, other):
        return super(SrcIp, self).__eq__(other) and self.ip_str == other.ip_str


class DstIp(AtomicPredicate):
    def __init__(self, ip_str):
        super(DstIp, self).__init__()
        self.ip_str = ip_str
        self.ipv4 = ':' not in ip_str
        if self.ipv4:
            self.fields_filter = {'eth_type': ETH_TYPE_IPV4, 'ipv4_dst': ip_str}
        else:
            self.fields_filter = {'eth_type': ETH_TYPE_IPV6, 'ipv6_dst': ip_str}
        self.matched_fields = self.fields_filter

    def _test(self, event):
        if not isinstance(event, PacketIn):
            return
        raw = event.msg.data
        pkt = packet.Packet(data=raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self.matched_fields = {'eth_type': ETH_TYPE_ARP, 'arp_dst_ip': self.ip_str}
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
        return (self.ipv4 and pkt_arp and pkt_arp.dst_ip == self.ip_str) or\
               (self.ipv4 and pkt_ipv4 and pkt_ipv4.dst == self.ip_str) or\
               (not self.ipv4 and pkt_ipv6 and pkt_ipv6.dst == self.ip_str)

    def conflicts_with(self, other):
        return predicate_conflict_helper(self, self.ip_str, other, other.ip_str)

    def __eq__(self, other):
        return super(DstIp, self).__eq__(other) and self.ip_str == other.ip_str


class EchoRequest(AtomicPredicate):
    def __init__(self):
        super(EchoRequest, self).__init__()
        self.fields_filter = {'icmpv4_type': icmp.ICMP_ECHO_REQUEST}
        self.matched_fields = self.fields_filter

    def _test(self, event):
        if not isinstance(event, PacketIn):
            return
        raw = event.msg.data
        pkt = packet.Packet(data=raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_icmpv6 = pkt.get_protocol(icmpv6.icmpv6)
        if pkt_icmpv6:
            self.matched_fields = {'icmpv6_type': icmpv6.ICMPV6_ECHO_REQUEST}
        return (pkt_icmp and pkt_icmp.type == icmp.ICMP_ECHO_REQUEST) or\
               (pkt_icmpv6 and pkt_icmpv6.type_ == icmpv6.ICMPV6_ECHO_REQUEST)


class ArpRequest(AtomicPredicate):
    def __init__(self):
        super(ArpRequest, self).__init__()
        self.fields_filter = {'arp_opcode': arp.ARP_REQUEST, 'eth_type': ETH_TYPE_ARP}
        self.matched_fields = self.fields_filter

    def _test(self, event):
        if not isinstance(event, PacketIn):
            return
        raw = event.msg.data
        pkt = packet.Packet(data=raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_arp = pkt.get_protocol(arp.arp)
        return pkt_arp and pkt_arp.opcode == arp.ARP_REQUEST


class ArpReply(AtomicPredicate):
    def __init__(self):
        super(ArpReply, self).__init__()
        self.fields_filter = {'arp_opcode': arp.ARP_REPLY, 'eth_type': ETH_TYPE_ARP}
        self.matched_fields = self.fields_filter

    def _test(self, event):
        if not isinstance(event, PacketIn):
            return
        raw = event.msg.data
        pkt = packet.Packet(data=raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_arp = pkt.get_protocol(arp.arp)
        return pkt_arp and pkt_arp.opcode == arp.ARP_REPLY


# Selectors


class RandomSelector(MemberSelector):
    def __init__(self, members):
        super(RandomSelector, self).__init__(members)

    def select(self, event):
        return [random.choice(self.members)]


class RoundRobinSelector(MemberSelector):
    def __init__(self, members):
        super(RoundRobinSelector, self).__init__(members)
        self.index = 0

    def select(self, event):
        ret = [self.members[self.index]]
        self.index = (self.index + 1) % len(self.members)
        return ret


class SelectLowestLoad(MemberSelector):
    def __init__(self, members):
        super(SelectLowestLoad, self).__init__(members)

    def select(self, event):
        if len(self.members) < 1:
            return []

        min_member = self.members[0]
        min_load = min_member.load

        for member in self.members:
            if member.load < min_load:
                min_member = member
                min_load = member.load

        return [min_member]


class SelectAll(MemberSelector):
    def __init__(self, members):
        super(SelectAll, self).__init__(members)

    def select(self, event):
        return self.members


# Actions


'''
Perform L2 Learning.

Adapted from ryu.app.simple_switch13
'''


class AutoARPProcessing(Action):
    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return
        msg = event.msg
        raw = msg.data
        pkt = packet.Packet(data=raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        pkt_arp = pkt.get_protocol(arp.arp)
        if not pkt_arp:
            return
        # remember source

        # find the switch connecting dst host
        r = host_mgr.query_host(ipv4=pkt_arp.dst_ip)
        if r:
            target_dpid, out_port = r
            target_dp = link_mgr.conns[target_dpid]
        else:
            return
        # send out
        ofproto = target_dp.ofproto
        parser = target_dp.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        data = event.msg.data
        out = parser.OFPPacketOut(datapath=target_dp, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        target_dp.send_msg(out)


class SetDstIp(Action):
    def __init__(self, ip_str):
        super(SetDstIp, self).__init__()

        self.ip_str = ip_str
        self.ipv4 = ':' not in ip_str

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        if ipv4:
            context.set_field({'ipv4_dst': self.ip_str})
        else:
            context.set_field({'ipv6_dst': self.ip_str})


class SetSrcIp(Action):
    def __init__(self, ip_str):
        super(SetSrcIp, self).__init__()

        self.ip_str = ip_str
        self.ipv4 = ':' not in ip_str

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        if ipv4:
            context.set_field({'ipv4_src': self.ip_str})
        else:
            context.set_field({'ipv6_src': self.ip_str})


class SetDstMac(Action):
    def __init__(self, mac):
        super(SetDstMac, self).__init__()

        self.mac = mac

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        context.set_field({'dst': self.mac})


class SetSrcMac(Action):
    def __init__(self, mac):
        super(SetSrcMac, self).__init__()

        self.mac = mac

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        context.set_field({'src': self.mac})


class SendArpReplyWith(Action):
    def __init__(self, mac):
        super(SendArpReplyWith, self).__init__()
        self.mac = mac

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        msg = event.msg
        in_port = msg.match['in_port']
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        raw = msg.data
        pkt = packet.Packet(data=raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_arp = pkt.get_protocol(arp.arp)

        a = arp.arp(hwtype=pkt_arp.hwtype, proto=pkt_arp.proto, hlen=pkt_arp.hlen, plen=pkt_arp.plen,
                    opcode=arp.ARP_REPLY, src_mac=self.mac, src_ip=pkt_arp.dst_ip, dst_mac=pkt_arp.src_mac,
                    dst_ip=pkt_arp.src_ip)
        e = ethernet.ethernet(dst=pkt_ethernet.src, src=self.mac, ethertype=ETH_TYPE_ARP)

        reply = packet.Packet()
        reply.add_protocol(e)
        reply.add_protocol(a)
        reply.serialize()

        actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=reply.data)
        datapath.send_msg(out)


class SendEchoReply(Action):
    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        msg = event.msg
        in_port = msg.match['in_port']
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        raw = msg.data
        pkt = packet.Packet(data=raw)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return False
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        ip = ipv4.ipv4(dst=pkt_ipv4.src, src=pkt_ipv4.dst, proto=pkt_ipv4.proto)
        ic = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0,
                       data=pkt_icmp.data)
        e = ethernet.ethernet(dst=pkt_ethernet.src, src=pkt_ethernet.dst, ethertype=ETH_TYPE_IPV4)
        reply = packet.Packet()
        reply.add_protocol(e)
        reply.add_protocol(ip)
        reply.add_protocol(ic)
        reply.serialize()

        actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions, data=reply.data)
        datapath.send_msg(out)


# TODO use FlowModContext
class L2Learn(Action):
    def __init__(self):
        super(L2Learn, self).__init__()

        self.mac_to_port = {}
        self.connected = False
        self.dpid = None
        self.flow_mod = True

    def perform(self, context):
        event = context.event
        if isinstance(event, ConnectionUp):
            self._handle_connection_up(event)
            return
        elif isinstance(event, ConnectionDown):
            self._handle_connection_down()
            return

        # check if switch not up yet
        if not self.connected:
            return
        if isinstance(event, PacketIn):
            self._handle_packet_in(event)

    def _handle_connection_up(self, event):
        self.connected = True
        self.connection = event.msg.datapath
        self.dpid = event.msg.datapath.id

    def _handle_connection_down(self):
        self.connected = False
        self.connection = None
        self.dpid = None

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def _handle_packet_in(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            ookm_log.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # check if not from my switch
        if datapath.id != self.dpid:
            ookm_log.warning("Not from my switch")
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        ookm_log.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # if in flow_modding_mode, install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD and self.flow_modding_mode:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
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


class ForwardProxy(Action):
    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return
        # TODO not implemented yet


class ApplyLink(Action):
    def __init__(self):
        super(ApplyLink, self).__init__()
        self.flow_mod = True

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        if isinstance(self.selector, Link):
            selection = [self.selector]
        elif isinstance(self.selector, Selector):
            selection = self._get_selection(event)
        else:
            ookm_log.error("A Link or Selector must be specified for ApplyLink")
            return

        if len(selection) < 1:
            ookm_log.warning("No link is selected to apply")
            return

        link = selection[0]
        ookm_log.debug("Apply link %s whose load is %d" % (link, link.load))

        switch_1_to_2 = link.switch1 == event.msg.datapath.id
        switch_2_to_1 = False
        if link.switch2:
            switch_2_to_1 = link.switch2 == event.msg.datapath.id

        if not (switch_1_to_2 or switch_2_to_1):
            ookm_log.warning("The link is not associated to the switch")
            return

        outport = link.port1
        if switch_2_to_1:
            outport = link.port2

        if self.flow_modding_mode:
            context.forward(outport)
        else:
            datapath = event.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(outport)]
            data = None
            if event.msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = event.msg.data
            in_port = event.msg.match['in_port']
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=event.msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)


class ForwardDefault(Action):
    def __init__(self):
        super(ForwardDefault, self).__init__()
        self.flow_mod = False

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        outport = ofproto.OFPP_NORMAL
        actions = [parser.OFPActionOutput(outport, ofproto.OFPCML_NO_BUFFER)]
        # send out the package if not in flow_modding_mode
        data = None
        if event.msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = event.msg.data
        in_port = event.msg.match['in_port']
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=event.msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


class ApplyLinkForEach(Action):
    def __init__(self):
        super(ApplyLinkForEach, self).__init__()
        self.flow_mod = True

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        if isinstance(self.selector, Link):
            selection = [self.selector]
        elif isinstance(self.selector, Selector):
            selection = self._get_selection(event)
        else:
            ookm_log.error("A Link or Selector must be specified for ApplyLink")
            return

        if len(selection) < 1:
            ookm_log.warning("No link is selected to apply")
            return

        link = selection[0]
        if not link.info_retrieved:
            ookm_log.debug("ApplyLinkForEach: Link not initialized")
            return
        ookm_log.debug("ApplyLinkForEach %s whose load is %d, flow_modding_mode: %s"
                       % (link, link.load, self.flow_modding_mode))

        switch_1_to_2 = link.switch1 == event.msg.datapath.id
        switch_2_to_1 = False
        if link.switch2:
            switch_2_to_1 = link.switch2 == event.msg.datapath.id

        if not (switch_1_to_2 or switch_2_to_1):
            ookm_log.warning("The link is not associated to the switch")
            return

        outport = link.port1
        if switch_2_to_1:
            outport = link.port2

        if self.flow_modding_mode:
            context.forward_for_each(outport)
        else:
            datapath = event.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(outport)]
            data = None
            if event.msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = event.msg.data
            in_port = event.msg.match['in_port']
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=event.msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)


class ApplyRouteForEach(Action):
    def __init__(self):
        super(ApplyRouteForEach, self).__init__()
        # It's too hard to include ApplyRouteForEach in rule compiling
        # so we just let flow_mod be False so it will be ignored when checking
        self.flow_mod = False

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        msg = event.msg
        datapath = msg.datapath

        if isinstance(self.selector, list):
            selection = [self.selector]
        elif isinstance(self.selector, Selector):
            selection = self._get_selection(event)
        else:
            ookm_log.error("A Link or Selector must be specified for ApplyLink")
            return

        if len(selection) < 1:
            ookm_log.debug("No route is selected to apply")
            return

        route = selection[0]
        first_link = route[0]
        if not first_link.info_retrieved:
            ookm_log.debug("ApplyRouteForEach: First Link not initialized")
            return
        # determine outport by first_link
        switch_1_to_2 = first_link.switch1 == datapath.id
        switch_2_to_1 = False
        if first_link.switch2:
            switch_2_to_1 = first_link.switch2 == datapath.id

        if not (switch_1_to_2 or switch_2_to_1):
            ookm_log.warning("The link is not associated to the switch")
            return

        outport = first_link.port1
        if switch_2_to_1:
            outport = first_link.port2

        # using OokmFlowModContext to instruct the first link
        context.forward_for_each(outport)

        remaining_links = route[1:]
        target = first_link.switch2
        if switch_2_to_1:
            target = first_link.switch1

        match = get_exact_match(msg)
        for link in remaining_links:
            if not link.info_retrieved:
                ookm_log.debug("ApplyRouteForEach: Link not initialized")
                return
            # get link direction
            switch_1_to_2 = link.switch1 == target
            switch_2_to_1 = False
            if link.switch2:
                switch_2_to_1 = link.switch2 == target
            if not (switch_1_to_2 or switch_2_to_1):
                ookm_log.warning("The link is not associated to the switch")
                return
            outport = link.port1
            if switch_2_to_1:
                outport = link.port2

            # send out flow_mod
            target_dp = link_mgr.conns[target]
            ofproto = target_dp.ofproto
            parser = target_dp.ofproto_parser
            actions = [parser.OFPActionOutput(outport)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            mod = parser.OFPFlowMod(datapath=target_dp, priority=4,
                                    match=match, instructions=inst,
                                    idle_timeout=10, hard_timeout=10)
            target_dp.send_msg(mod)

            # determine next target dp
            target = link.switch2
            if switch_2_to_1:
                target = link.switch1


class ApplyController(Action):
    def __init__(self):
        super(ApplyController, self).__init__()
        self.flow_mod = True

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return


        datapath = event.msg.datapath
        ofproto = datapath.ofproto
        outport = ofproto.OFPP_CONTROLLER
        if self.flow_modding_mode:
            context.forward(outport, ofproto.OFPCML_NO_BUFFER)
        else:
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionOutput(outport, ofproto.OFPCML_NO_BUFFER)]
            data = None
            if event.msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = event.msg.data
            in_port = event.msg.match['in_port']
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=event.msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)


class SimpleForward(Action):
    def __init__(self, port):
        super(SimpleForward, self).__init__()
        self.port = port
        self.fall_through = False

    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            return

        datapath = event.msg.datapath
        in_port = event.msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(self.port)]
        data = None
        if event.msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = event.msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=event.msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


class DebugPrint(Action):
    def perform(self, context):
        event = context.event
        ookm_log.debug('Debug Print!')
        ookm_log.debug('  Event :%s', event)


class PrintPacketType(Action):
    def perform(self, context):
        event = context.event
        if not isinstance(event, PacketIn):
            ookm_log.info("Not PacketIn, %s", event)
        msg = event.msg
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
        ookm_log.info("*****")
        if pkt_arp:
            ookm_log.info("PKT_ARP")
        if pkt_ipv4:
            ookm_log.info("PKT_IPV4")
        if pkt_ipv6:
            ookm_log.info("PKT_IPV6")
        if pkt_icmp:
            ookm_log.info("PKT_ICMP")
        if pkt_icmpv6:
            ookm_log.info("PKT_ICMPV6")
        if pkt_tcp:
            ookm_log.info("PKT_TCP")
        if pkt_udp:
            ookm_log.info("PKT_UDP")


# Entities


class Host(object):
    def __init__(self, ip=None, mac=None):
        self.ipv4 = None
        self.ipv6 = None
        if ip:
            if ':' not in ip:
                self.ipv4 = ip
            else:
                self.ipv6 = ip
        if mac:
            self.mac = mac
        if not (ip or mac):
            ookm_log.error("Must specify ip or mac in Host(...)")
            return

        host_mgr.register_object(self)

    def _get_statistic(self, key):
        from ookm.framework.core import host_mgr
        return host_mgr.query_statistic(self, key)

    # override a host's load here, using _get_statistic to get statistic info
    @property
    def load(self):
        return 0


class Link(object):
    # called by link manager
    def get_link_info_cb(self):
        if self.switch_port and not (self.switch_switch or self.switch_host):
            self.switch1, self.port1, self.switch2, self.port2 = link_mgr.query_link(
                switch1=self.switch_port[0], port1=self.switch_port[1])
        elif self.switch_switch and not (self.switch_port or self.switch_host):
            self.switch1, self.port1, self.switch2, self.port2 = link_mgr.query_link(
                switch1=self.switch_switch[0], switch2=self.switch_switch[1])
        elif self.switch_host and not (self.switch_port or self.switch_switch):
            self.switch1, self.port1, _, _ = link_mgr.query_link(
                switch1=self.switch_host[0], host=self.switch_host[1])
            self.switch2 = None
            self.port2 = None
        else:
            # invalid parameters
            ookm_log.error("Invalid parameter for Link()")
            raise RuntimeError()

        # if any info is returned by link_mgr.query_link()
        if self.switch1 or self.switch2 or self.port1 or self.port2:
            self.info_retrieved = True
            link_mgr.links.remove(self)
            ookm_log.info("Retrieved info of link %s", self.__str__())

    def __init__(self, switch_port=None, switch_switch=None, switch_host=None):
        # full link info is not retrieved when Link object is created
        # link manager will call get_link_info_cb() later and fill these info
        self.info_retrieved = False
        self.switch_port = switch_port
        self.switch_switch = switch_switch
        self.switch_host = switch_host
        self.switch1=None
        self.switch2=None
        self.port1=None
        self.port2=None
        link_mgr.register_object(self)

    def __str__(self):
        if not self.info_retrieved:
            return "Uninitialized"
        elif self.switch2:
            return "'%s[%d]' => '%s[%d]'" % (
                self.switch1,
                self.port1,
                self.switch2,
                self.port2)
        else:
            return "'%s[%d]' => Host" % (
                self.switch1,
                self.port1)

    @property
    def load(self):
        stats = link_mgr.query_load(self.switch1, self.port1)
        return stats.get('tx_speed', 0) + stats.get('rx_speed', 0)

    @property
    def usage(self):
        stats = link_mgr.query_load(self.switch1, self.port1)
        return stats.get('tx_bytes', 0) + stats.get('rx_bytes', 0)


class VirtualGateway(object):
    def __init__(self, ip_str, mac, dpid, port):
        self.ip_str = ip_str
        self.mac = mac

        self.dpid = dpid

        self.port = port

        self._install_default_rules()

    def _install_default_rules(self):
        # The makes the gateway reply to arp requests.
        (FromSwitch(self.dpid) & InPort(self.port) & DstIp(self.ip_str) & ArpRequest()) >> \
            [SendArpReplyWith(self.mac)]

        # This makes the gateway reply to echo requests.
        (FromSwitch(self.dpid) & InPort(self.port) & DstIp(self.ip_str) & EchoRequest()) >> \
            [SendEchoReply()]

        # This allows arp request to go out.
        (FromSwitch(self.dpid) & ~InPort(self.port) & ArpRequest()) >> \
            [SimpleForward(self.port)]

        # This allows arp reply to go in.
        (FromSwitch(self.dpid) & InPort(self.port) & ArpReply()) >> \
            [SimpleForward(ofproto_v1_3.OFPP_FLOOD)]
