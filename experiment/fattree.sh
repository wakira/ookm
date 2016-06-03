#!/bin/bash
sudo mn --controller=remote,ip=127.0.0.1 --custom=topo-fat-tree.py --topo=fattree --switch=ovsk,protocol=OpenFlow13 --mac
