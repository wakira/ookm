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


class Selector(Node):
    def __init__(self, members, name='Sel'):
        super(Selector, self).__init__(name)
        self.members = sorted(members, key=lambda x: x.__hash__())

    def all_members(self):
        return self.members

    def select(self, event):
        return []

    def __eq__(self, other):
        return self.identifier() == other.identifier() and self.all_members() == other.all_members()

    def debug_print(self, indent=0):
        Selector._print_indent(self.name, indent)
