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
from ookm.lang.selector import Selector


class Action(Node):
    def __init__(self, name='Act'):
        super(Action, self).__init__(name)

        self.rule = None
        self.selector = None
        self.flow_mod = False
        self.flow_modding_mode = True  # Only affects Actions with flow_mod true

    def __mod__(self, rhs):
        Action._validate_rhs(rhs)
        self.selector = rhs
        return self

    def _get_selection(self, event):
        if self.selector:
            return self.selector.select(event)
        else:
            return []

    def perform(self, context):
        pass

    def conflicts_with_actions(self, act_lst):
        if self.flow_mod:
            return any(x.flow_mod for x in act_lst)
        else:
            return False

    def debug_print(self, indent=0):
        Action._print_indent(self.name, indent)
        self._debug_print_selector(indent)

    def _debug_print_selector(self, indent):
        if self.selector:
            self.selector.debug_print(indent + 1)

    @classmethod
    def _validate_rhs(cls, rhs):
        if not rhs:
            raise Exception('Not \'Selector\' after \'%\'')
