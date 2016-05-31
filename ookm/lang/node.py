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


class Node(object):
    def __init__(self, name = 'Node'):
        self.name = name

    def debug_print(self, indent = 0):
        Node._print_indent(self.name, indent)

    @classmethod
    def identifier(cls):
        return cls.__name__

    def __eq__(self, other):
        return isinstance(other, Node) and self.identifier() == other.identifier()

    @classmethod
    def _print_indent(cls, name, indent):
        padded_len = indent * 2 + len(name)
        print(name.rjust(padded_len, '-'))
