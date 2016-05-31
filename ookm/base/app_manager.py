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

from os import environ

import ryu.topology as topology
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

import ookm.base.event as ookm_event
import ookm.framework.core as core
from ookm.base.nal_interface import OokmFlowModContext


# This file contains the underlying interface of Ryu app
# It boots up the core and loads user program from environment variables
# all Ryu events are processed using core mechanisms


class OokmRyuCore(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OokmRyuCore, self).__init__(*args, **kwargs)
        # start link manager, host manager ... etc
        core.startup(logger=self.logger)

        # load rules in user program
        program_name = environ.get("OOKM_PROGRAM")
        core.rule_mgr.load_program(program_name)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        event = None
        if ev.state == MAIN_DISPATCHER:
            # switch registry is now done in topology discovery instead
            # core.link_mgr.register_switch(datapath.id, datapath)
            event = ookm_event.ConnectionUp(ev)
        elif ev.state == DEAD_DISPATCHER:
            # switch registry is now done in topology discovery instead
            # core.link_mgr.unregister_switch(datapath.id, datapath)
            event = ookm_event.ConnectionDown(ev)
        OokmRyuCore._handle_event(event)

    @set_ev_cls(topology.event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        core.link_mgr.register_switch(ev.switch.dp.id, ev.switch.dp)
        core.link_mgr.update_topology(self)

    @set_ev_cls(topology.event.EventSwitchLeave)
    def _switch_leave_handler(self, ev):
        core.link_mgr.unregister_switch(ev.switch.dp.id)
        core.link_mgr.update_topology(self)

    # TODO do more
    @set_ev_cls(topology.event.EventLinkAdd)
    def _link_add_handler(self, ev):
        core.link_mgr.register_link(ev.link.src, ev.link.dst)
        core.link_mgr.update_topology(self)

    @set_ev_cls(topology.event.EventLinkDelete)
    def _link_delete_handler(self, ev):
        core.link_mgr.unregister_link(ev.link.src, ev.link.dst)
        core.link_mgr.update_topology(self)

    @set_ev_cls(topology.event.EventHostAdd)
    def _host_add_handler(self, ev):
        core.host_mgr.register_host(ev.host)
        core.link_mgr.update_topology(self)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @staticmethod
    def _handle_event(event):
        context = OokmFlowModContext(event)
        all_matched_fields = {}
        for rule in core.rule_mgr.rules:
            if rule.test_predicate(event):
                for p in rule.predicate:
                    all_matched_fields = dict(all_matched_fields, **p.matched_fields)
                rule.perform_actions(context)
        context.perform(all_matched_fields)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self._handle_event(ookm_event.PacketIn(ev))

    '''
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_handler(self, ev):
        self._packet_in_handler(ev)
    '''

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        core.link_mgr.handle_port_stats(ev)

    '''
    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def _error_msg_handler(self, ev):
        self._packet_in_handler(ev)
    '''
