#!/bin/bash
sudo mn --controller=remote,ip=127.0.0.1 --custom=dbktest.py --topo=dbktest --switch=ovsk,protocol=OpenFlow13 --mac
