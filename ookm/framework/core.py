# Copyright 2013 Li Cheng <licheng at microsoft com>
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

import time
import threading
import copy
import importlib
import websockets
import asyncio
import json
from ookm.lang.predicate import predicates_intersects
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from operator import attrgetter
from argparse import ArgumentError


class Logger(object):
    def __init__(self):
        self._logger = None

    def set_logger(self, logger):
        self._logger = logger

    def debug(self, msg, *args, **kwargs):
        self._logger.debug(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self._logger.info(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self._logger.error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self._logger.critical(msg, *args, **kwargs)

ookm_log = Logger()


class RuleManager(object):
    def __init__(self):
        self.rules = []

    def load_program(self, name):
        if name is None:
            ookm_log.critical("Specify correct ookm program with OOKM_PROGRAM environment variable!")
            exit(1)
        ookm_log.info("Loading program %s", name)
        try:
            user_module = importlib.import_module(name)
            user_module.run()
        except RuntimeError:
            ookm_log.info("Error loading program %s", name)
            exit(1)
        ookm_log.info("%s loaded", name)

    def register(self, rule):
        if not rule.predicate:
            raise RuntimeError('No predicate in the rule \'%s\'' % rule.name)

        # suppress duplicate rules, usually generated by ApplyRouteForEach
        if rule in self.rules:
            return

        inter_rules_list = []
        no_intersection = True
        # Forwarding to controller is needed when FlowMod and non FlowMod meets
        forward_to_controller = not all(x.flow_mod for x in rule.actions)
        for old_rule in self.rules:
            # intersection of predicate
            if predicates_intersects(rule.predicate, old_rule.predicate):
                no_intersection = False
                # action conflict check and add to inter_rules_list if passed, conflict warning otherwise
                action_conflict = any(x.conflicts_with_actions(old_rule.actions) for x in rule.actions)
                if action_conflict:
                    ookm_log.error("%s introduces conflict!", rule.name)
                    raise RuntimeError("Rule Conflict")
                inter_rules_list.append(old_rule)
                forward_to_controller = not all(x.flow_mod for x in old_rule.actions + rule.actions)

        if no_intersection:
            self._add_rule(rule)
        else:
            if forward_to_controller:
                for old_rule in inter_rules_list:
                    for act in old_rule.actions:
                        act.flow_modding_mode = False
                for act in rule.actions:
                    act.flow_modding_mode = False
            self._add_rule(rule)

    # helper function for register
    # checks if there is already the same rule
    def _add_rule(self, rule):
        no_duplicate = True
        for old_rule in self.rules:
            if rule.predicate == old_rule.predicate and rule.actions == old_rule.actions:
                no_duplicate = False
                break
        if no_duplicate:
            self.rules.append(rule)

    def count(self):
        return len(self.rules)

rule_mgr = RuleManager()


class _LinkStats(object):
    def __init__(self, s1, p1):
        self.switch1 = s1
        self.port1 = p1
        self.stats = dict()

# TODO add locks to prevent race conditions
class LinkManager(object):
    def __init__(self):
        self.links = []  # links that has been used in user programs
        self.conns = {}  # dpid: dp
        self._topo_raw_switches = []
        self._topo_raw_links = []
        self.links_with_stats = []
        self.went_down = False

    def register_object(self, link):
        self.links.append(link)

    def query_link(self, switch1=None, port1=None, switch2=None, host=None):
        if switch1:
            found = None
            if switch2:
                found = list(filter(lambda l: l.src.dp.id == switch1.dpid and l.dst.dpid == switch2,
                                    self._topo_raw_links))
            elif port1:
                found = list(filter(lambda l: l.src.dpid == switch1.dpid and l.src.port_no == port1,
                                    self._topo_raw_links))
            elif host:
                r = None
                if host.ipv4:
                    r = host_mgr.query_host(ipv4=host.ipv4)
                elif host.ipv6:
                    r = host_mgr.query_host(ipv6=host.ipv6)
                elif host.mac:
                    r = host_mgr.query_host(ipv6=host.mac)
                else:
                    return None, None, None, None
                if r:
                    found_dpid, found_port = r
                else:
                    return None, None, None, None
                return found_dpid, found_port, None, None
            if found:
                return switch1.dpid, found[0].src.port_no, found[0].dst.dpid, found[0].dst.port_no
        return None, None, None, None

    def count(self):
        return len(self.links)

    def startup(self):
        t = threading.Thread(target=self.worker, args=[])
        t.start()

    def shutdown(self):
        self.went_down = True

    def update_topology(self, app):
        self._topo_raw_switches = copy.copy(get_all_switch(app))
        self._topo_raw_links = copy.copy(get_all_link(app))
        ookm_log.debug("Topology updated")

    def register_switch(self, id, datapath):
        if id not in self.conns:
            ookm_log.info('register switch %016x', id)
        self.conns[id] = datapath

    def unregister_switch(self, id):
        if id in self.conns:
            ookm_log.info('unregister switch %016x', id)
            del self.conns[id]

    def register_link(self, src, dst):
        ookm_log.debug("register link! %s, %s", src, dst)
        for obj in self.links:
            if not obj.info_retrieved:
                obj.get_link_info_cb()

    # TODO implement link failover
    def unregister_link(self, src, dst):
        pass

    def handle_port_stats(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            found = list(filter(lambda ls: ls.switch1 == dpid and ls.port1 == port_no, self.links_with_stats))
            if found:
                found[0].stats['rx_packets'] = stat.rx_packets
                found[0].stats['rx_bytes'] = stat.rx_bytes
                found[0].stats['rx_errors'] = stat.rx_errors
                found[0].stats['tx_packets'] = stat.tx_packets
                found[0].stats['tx_bytes'] = stat.tx_bytes
                found[0].stats['tx_errors'] = stat.tx_errors
            else:
                ls = _LinkStats(dpid, port_no)
                ls.stats['rx_packets'] = stat.rx_packets
                ls.stats['rx_bytes'] = stat.rx_bytes
                ls.stats['rx_packets'] = stat.rx_errors
                ls.stats['tx_packets'] = stat.tx_packets
                ls.stats['tx_bytes'] = stat.tx_bytes
                ls.stats['tx_packets'] = stat.tx_errors
                self.links_with_stats.append(ls)

    def query_load(self, s1, p1):
        found = list(filter(lambda ls: ls.switch1 == s1 and ls.port1 == p1, self.links_with_stats))
        if found:
            return found[0].stats
        else:
            return {}

    def worker(self):
        while not self.went_down:
            for dpid in self.conns:
                conn = self.conns[dpid]
                ofproto = conn.ofproto
                parser = conn.ofproto_parser
                req = parser.OFPPortStatsRequest(conn, 0, ofproto.OFPP_ANY)
                conn.send_msg(req)
            for link in self.links:
                if not link.info_retrieved:
                    link.get_link_info_cb()
            time.sleep(1)

link_mgr = LinkManager()


class HostManager(object):
    def __init__(self):
        self.hosts = []  # hosts that has been used in user programs
        self._topology_raw_hosts = []
        self.lock = threading.Lock()
        self.mac_to_load = dict()

    def query_host(self, ipv4=None, ipv6=None, mac=None):
        found = None
        if ipv4:
            found = list(filter(lambda h: ipv4 in h.ipv4, self._topology_raw_hosts))
        elif ipv6:
            found = list(filter(lambda h: ipv6 in h.ipv6, self._topology_raw_hosts))
        elif mac:
            found = list(filter(lambda h: h.mac == mac, self._topology_raw_hosts))
        if found:
            return found[0].port.dpid, found[0].port.port_no
        else:
            return None

    def query_statistic(self, host, key):
        return self.mac_to_load[host.mac][key]

    def register_object(self, host_obj):
        self.hosts.append(host_obj)

    def register_host(self, host):
        self._topology_raw_hosts.append(host)

    def count(self):
        return len(self.hosts)

    async def serve_client(self, websocket, path):
        data = await websocket.recv()
        data_dict = json.loads(data)
        if 'mac' and 'timestamp' not in data_dict:
            return
        sender = data_dict['mac']
        timestamp = data_dict['timestamp']
        data_dict.pop('mac')
        data_dict.pop('timestamp')
        with self.lock:
            if sender not in self.mac_to_load:
                self.mac_to_load[sender] = dict()
            for key in data_dict:
                if self.mac_to_load[sender].get(key+'_ts', 0) <= timestamp:
                    self.mac_to_load[sender][key+'_ts'] = timestamp
                    self.mac_to_load[sender][key] = data_dict[key]

    def worker(self):
        start_server = websockets.serve(self.serve_client, 'localhost', 12345)
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
        event_loop.run_until_complete(start_server)
        event_loop.run_forever()

    def startup(self):
        t = threading.Thread(target=self.worker, args=[])
        t.start()

host_mgr = HostManager()


def startup(logger=None):
    # Rule for processing all unmatched packets.
    # Anything() >> [ PrintEvent() ]

    ookm_log.set_logger(logger)
    link_mgr.startup()
    host_mgr.startup()