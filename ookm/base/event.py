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


# This package contains simple warp of PacketIn and PortStatusChange events
# for consistent processing in predicates definition


class OokmEvent(object):
    def __init__(self, msg=None):
        self.msg = msg


class PacketIn(OokmEvent):
    def __init__(self, ofp_event):
        super(PacketIn, self).__init__(ofp_event.msg)
        # TODO extract common header fields for easier use


class ConnectionUp(OokmEvent):
    def __init__(self, ofp_event):
        super(ConnectionUp, self).__init__(ofp_event)


class ConnectionDown(OokmEvent):
    def __init__(self, ofp_event):
        super(ConnectionDown, self).__init__(ofp_event)
