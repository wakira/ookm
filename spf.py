from ookm.framework.ryulib import *
from ookm.framework.predefined import ShortestPathForwarding


def run():
    h1 = Host(ip='10.0.0.1', mac='00:00:00:00:00:01')
    h2 = Host(ip='10.0.0.2', mac='00:00:00:00:00:02')
    h3 = Host(ip='10.0.0.3', mac='00:00:00:00:00:03')
    h4 = Host(ip='10.0.0.4', mac='00:00:00:00:00:04')
    h5 = Host(ip='10.0.0.5', mac='00:00:00:00:00:05')
    h6 = Host(ip='10.0.0.6', mac='00:00:00:00:00:06')
    h7 = Host(ip='10.0.0.7', mac='00:00:00:00:00:07')
    h8 = Host(ip='10.0.0.8', mac='00:00:00:00:00:08')
    h9 = Host(ip='10.0.0.9', mac='00:00:00:00:00:09')
    h10 = Host(ip='10.0.0.10', mac='00:00:00:00:00:0a')
    h11 = Host(ip='10.0.0.11', mac='00:00:00:00:00:0b')
    h12 = Host(ip='10.0.0.12', mac='00:00:00:00:00:0c')
    h13 = Host(ip='10.0.0.13', mac='00:00:00:00:00:0d')
    h14 = Host(ip='10.0.0.14', mac='00:00:00:00:00:0e')
    h15 = Host(ip='10.0.0.15', mac='00:00:00:00:00:0f')
    h16 = Host(ip='10.0.0.16', mac='00:00:00:00:00:10')
    ArpReply() >> [AutoARPProcessing()]
    ArpRequest() >> [AutoARPProcessing()]
    (Anything() & ~ArpReply() & ~ArpRequest()) >> [ApplyRouteForEach() % ShortestPathForwarding()]
