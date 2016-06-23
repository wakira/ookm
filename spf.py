from ookm.framework.ryulib import *
from ookm.framework.predefined import ShortestPathForwarding


def run():
    ArpReply() >> [AutoARPProcessing()]
    ArpRequest() >> [AutoARPProcessing()]
    (Anything() & ~ArpReply() & ~ArpRequest()) >> [ApplyRouteForEach() % ShortestPathForwarding()]
