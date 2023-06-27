#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
customize.py: Simple FRR MPLS L3VPN test topology

           |                                           |
      +----+----+                                 +----+----+
      |   ce1   |                                 |   ce2   |
      | 99.0.0.1|                                 | 99.0.0.2|                                         CE Router
      +----+----+                                 +----+----+
192.168.1. | .2  ce1-eth0                   192.168.1. | .2  ce2-eth0
           | .1  pe1-eth4                              | .1  pe2-eth4
      +----------------------+           +----------------------+
      |         pe1          |           |         pe2          |
      |       1.1.1.1        |           |       2.2.2.2        |                  PE Router
      | fd00:0:200:171::/128 |           | fd00:0:200:172::/128 |
      +----------------------+           +----------+-----------+
 abcd:100:171:251::1| pe1-eth0             pe2-eth0 | abcd:100:172:161::1
                    |                      _________|
                     |                    / 
 abcd:100:171:251::2 | r1-eth0    r1-eth1| abcd:100:172:161::2
                    +----------------------+
                    |         r1           |
                    |       5.5.5.5        |                              P router/RR router
                    | fd00:0:200:101::/128 |
                    +----------------------+
  abcd:100:181:251::2 | r1-eth2   r1-eth3|abcd:100:182:161::2
                 ____/                    \____
                /                              \
                 |                              |
                  \                              |
                   \                             \
 abcd:100:181:251::1 | pe3-eth0          pe4-eth0 | abcd:100:182:161::1
      +-----------+----------+         +----------+-----------+
      |         pe3          |         |         pe4          | 
      |       3.3.3.3        |         |       4.4.4.4        |               PE Routers
      | fd00:0:200:181::/128 |         | fd00:0:200:182::/128 |
      +------------+---------+         +------------+---------+       
       192.168.1.1 |pe3.eth4            192.168.1.1 | pe4-eth4    
                .2 |ce3-eth0                     .2 | ce4-eth0
             +-----+-----+                     +----+-----+ 
             |    ce3    |                     |   ce4    | 
             | 99.0.0.3  |                     | 99.0.0.4 |              CE Routers
             +-----+-----+                     +----+-----+ 
                   |                                |      
       
"""

import os
import re
import pytest
import platform

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.ltemplate import ltemplateRtrCmd

# Required to instantiate the topology builder class.
from mininet.topo import Topo

import shutil

CWD = os.path.dirname(os.path.realpath(__file__))
# test name based on directory
TEST = os.path.basename(CWD)


def build_topo(tgen):
    # This function only purpose is to define allocation and relationship
    # between routers, switches and hosts.
    #
    # Create P/PE routers
    # check for mpls
    tgen.add_router("r1")

    for routern in range(1, 5):
        tgen.add_router("pe{}".format(routern))
    # Create CE routers
    for routern in range(1, 5):
        tgen.add_router("ce{}".format(routern))
        # CE/PE links
    tgen.add_link(tgen.gears["ce1"], tgen.gears["pe1"], "ce1-eth0", "pe1-eth4")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["pe2"], "ce2-eth0", "pe2-eth4")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["pe3"], "ce3-eth0", "pe3-eth4")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["pe4"], "ce4-eth0", "pe4-eth4")

    # PE/RR links
    # empty network.
    tgen.add_link(tgen.gears["pe1"], tgen.gears["r1"], "pe1-eth0", "r1-eth0")
    tgen.add_link(tgen.gears["pe2"], tgen.gears["r1"], "pe2-eth0", "r1-eth1")
    tgen.add_link(tgen.gears["pe3"], tgen.gears["r1"], "pe3-eth0", "r1-eth2")
    tgen.add_link(tgen.gears["pe4"], tgen.gears["r1"], "pe4-eth0", "r1-eth3")


def ltemplatePreRouterStartHook():
    cc = ltemplateRtrCmd()
    krel = platform.release()
    tgen = get_topogen()
    logger.info("pre router-start hook, kernel=" + krel)

    # trace errors/unexpected output
    cc.resetCounts()
    # configure r2 mpls interfaces

    # configure cust1 VRFs & MPLS
    rtrs = ["pe1", "pe2", "pe3", "pe4"]
    cmds = [
        "ip link add PUBLIC-TC0 type vrf table 10",
        "ip ru add oif PUBLIC-TC0 table 10",
        "ip ru add iif PUBLIC-TC0 table 10",
        "ip link set dev PUBLIC-TC0 up",
    ]
    for rtr in rtrs:
        for cmd in cmds:
            cc.doCmd(tgen, rtr, cmd.format(rtr))
        cc.doCmd(tgen, rtr, "ip link set dev {0}-eth4 master PUBLIC-TC0".format(rtr))
    # set PUBLIC-TC1 to redistribute
    cmds = [
        "ip link add PUBLIC-TC1 type vrf table 10",
        "ip ru add oif PUBLIC-TC1 table 10",
        "ip ru add iif PUBLIC-TC1 table 10",
        "ip link set dev PUBLIC-TC1 up",
    ]
    for rtr in rtrs:
        for cmd in cmds:
            cc.doCmd(tgen, rtr, cmd.format(rtr))

    # set PRIVATE-TC0
    cmds = [
        "ip link add PRIVATE-TC0 type vrf table 10",
        "ip ru add oif PRIVATE-TC0 table 10",
        "ip ru add iif PRIVATE-TC0 table 10",
        "ip link set dev PRIVATE-TC0 up",
    ]
    for rtr in rtrs:
        for cmd in cmds:
            cc.doCmd(tgen, rtr, cmd.format(rtr))
        #cc.doCmd(tgen, rtr, "ip link set dev {0}-eth4 master PRIVATE-TC0".format(rtr))
    # configure cust2 VRFs & MPLS
    """
    rtrs = ["pe1"]
    cmds = [
        "ip link add {0}-cust2 type vrf table 20",
        "ip ru add oif {0}-cust2 table 20",
        "ip ru add iif {0}-cust2 table 20",
        "ip link set dev {0}-cust2 up",
    ]
    for rtr in rtrs:
        for cmd in cmds:
            cc.doCmd(tgen, rtr, cmd.format(rtr))
        cc.doCmd(tgen, rtr, "ip link set dev {0}-eth5 master {0}-cust2".format(rtr))
    """
    if cc.getOutput() != 0:
        InitSuccess = False
        logger.info(
            "Unexpected output seen ({} times, tests will be skipped".format(
                cc.getOutput()
            )
        )
    else:
        InitSuccess = True
        logger.info("VRF config successful!")
    return InitSuccess


def ltemplatePostRouterStartHook():
    logger.info("post router-start hook")
    return True
