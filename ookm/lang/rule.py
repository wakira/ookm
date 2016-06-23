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

from ookm.lang.node import Node


class Rule(Node):
    def __init__(self, name=None, pred=None, acts=None):
        super(Rule, self).__init__(Rule._get_name(name))

        self.predicate = pred
        for predicate in self.predicate:
            predicate.rule = self
        self.actions = acts
        for action in self.actions:
            action.rule = self
        self.fall_through = all(x.fall_through for x in self.actions)
        from ookm.framework.core import rule_mgr
        rule_mgr.register(self)

    def __eq__(self, other):
        return isinstance(other, Rule) and self.predicate == other.predicate and\
                                       self.actions == other.actions

    def test_predicate(self, event):
        return all(p.test(event) for p in self.predicate)

    def perform_actions(self, context):
        for action in self.actions:
            action.perform(context)

    def debug_print(self, indent=0):
        Rule._print_indent(self.name, indent)
        self._debug_print_predicate(indent)
        self._debug_print_actions(indent)

    def _debug_print_predicate(self, indent):
        for p in self.predicate:
            p.debug_print(indent + 1)

    def _debug_print_actions(self, indent):
        for action in self.actions:
            action.debug_print(indent + 1)

    rid = 1

    @classmethod
    def _get_name(cls, name):
        if not name:
            name = 'Rule%d' % Rule.rid
            Rule.rid += 1

        return name
