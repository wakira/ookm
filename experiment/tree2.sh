#!/bin/bash
sudo mn --controller=remote,ip=127.0.0.1 --switch=ovsk,protocols=OpenFlow13 --mac --topo tree,depth=2
