#!/usr/bin/env python

#
# <template>.py
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
<template>.py: Test <template>.
"""

import os
import sys
import pytest
import json
import re
import time
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo
from mininet.net import Mininet


"""
test_sbfd_multi_path_topo3.py:

                         +---------+
                         |         |
             +-----------|   R1    |-----------+
             | eth-rt2   | 3001::1 | eth-rt3   |
             |           |         |           |
             |           +---------+           |
             |  2012::/64                      |  2013::/64 
             |                                 |
             |                                 |
             | eth-rt1                eth-rt1  |
         +---------+                     +---------+
         |         |                     |         |
         |   R2    |                     |   R3    |
         | 3001::2 +                     + 3001::3 |
         |         |                     |         |
         +---------+                     +---------+
    eth-rt4-1|  |eth-rt4-2          eth-rt5-1|  |eth-rt5-2
             |  |                            |  |
  2024:1::/64|  |2024:2::/64     2035:1::/64 |  |2035:2::/64
             |  |                            |  |
    eth-rt2-1|  |eth-rt2-2          eth-rt3-1|  |eth-rt3-2
         +---------+                     +---------+
         |         |                     |         |
         |   R4    |                     |   R5    |
         | 3001::4 +                     + 3001::5 |
         |         |eth-rt5       eth-rt4|         |
         +---------+                     +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   2046::/64  |                                |2056::/64 
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+ 6.6.6.6 +-----------+
                  eth-rt4|         |eth-rt5
                         +---------+
"""

def show_policy_selected_check(router, policy, sta_policy, pref):
    output = router.cmd("vtysh -c 'show sr-te policy name {} detail'".format(policy))
    # check policy state    
    pattern1 = re.compile(r'{}.*{}'.format(policy, sta_policy))
    ret = pattern1.findall(output)
    assert len(ret) > 0, output

    # check selected Preference state    
    pattern2 = re.compile(r'\* Preference: {}'.format(pref))
    ret = pattern2.findall(output)
    assert len(ret) > 0, output

def show_policy_check(router, policy, sta_policy, pref, sta_pref, cpath, sta_cpath):
    output = router.cmd("vtysh -c 'show sr-te policy name {} detail'".format(policy))
    # check policy state    
    pattern1 = re.compile(r'{}.*{}'.format(policy, sta_policy))
    ret = pattern1.findall(output)
    assert len(ret) > 0, output

    # check Preference state    
    pattern2 = re.compile(r'Preference: {}.*Status: {}'.format(pref, sta_pref))
    ret = pattern2.findall(output)
    assert len(ret) > 0, output

    # check Cpath
    pattern3 = re.compile(r'Candidate.*{}.*Status: {}'.format(cpath, sta_cpath))
    ret = pattern3.findall(output)
    assert len(ret) > 0, output

def show_bfd_specific_check(router, sidlist, sta):
    output = router.cmd("vtysh -c 'show bfd peers'")
    # check sidlsit 
    pattern1 = re.compile(r'sidlist {}{}Status: {}'.format(sidlist, '[\s\S]{1,200}', sta))
    ret = pattern1.findall(output)
    assert len(ret) > 0, output
    
def show_bfd_check(router, sidlist, sta, type='echo'):
    output = router.cmd("vtysh -c 'show bfd peers'")
    # check sidlsit 
    pattern1 = re.compile(r'sidlist {}'.format(sidlist))
    ret = pattern1.findall(output)
    assert len(ret) > 0, output

    # check  state
    pattern2 = re.compile(r'Status: {}'.format(sta))
    ret = pattern2.findall(output)
    assert len(ret) > 0, output

    # check type
    pattern3 = re.compile(r'Peer Type: {}'.format(type))
    ret = pattern3.findall(output)
    assert len(ret) > 0, output
class SBFDTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # This function only purpose is to define allocation and relationship
        # between routers, switches and hosts.
        #
        # Example
        #
        # Create 2 routers
        for routern in range(1, 7):
            tgen.add_router('r{}'.format(routern))

        # Create a switch with just one router connected to it to simulate a
        # empty network.
        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r3'])

        switch = tgen.add_switch('s3')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r4'])

        switch = tgen.add_switch('s4')
        switch.add_link(tgen.gears['r2'])
        switch.add_link(tgen.gears['r4'])

        switch = tgen.add_switch('s5')
        switch.add_link(tgen.gears['r3'])
        switch.add_link(tgen.gears['r5'])

        switch = tgen.add_switch('s6')
        switch.add_link(tgen.gears['r3'])
        switch.add_link(tgen.gears['r5'])

        switch = tgen.add_switch('s7')
        switch.add_link(tgen.gears['r4'])
        switch.add_link(tgen.gears['r6'])

        switch = tgen.add_switch('s8')
        switch.add_link(tgen.gears['r5'])
        switch.add_link(tgen.gears['r6'])

def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(SBFDTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
    cmd1 = "sysctl -w net.ipv6.conf.all.seg6_enabled=1"
    cmd2 = "sysctl -w net.ipv6.conf.default.seg6_enabled=1"
    cmd3 = "sysctl -w net.ipv6.conf.{}-eth0.seg6_enabled=1"
    cmd4 = "sysctl -w net.ipv6.conf.{}-eth1.seg6_enabled=1"
    cmd5 = "sysctl -w net.ipv6.conf.{}-eth2.seg6_enabled=1"
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_PATH,
            os.path.join(CWD, '{}/pathd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BFD,
            os.path.join(CWD, '{}/bfdd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC,
            os.path.join(CWD, '{}/staticd.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, 
            os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.run(cmd1)
        router.run(cmd2)
        exec_cmd = cmd3.format(rname)
        router.run(exec_cmd)
        exec_cmd = cmd4.format(rname)
        router.run(exec_cmd)
        exec_cmd = cmd5.format(rname)
        router.run(exec_cmd)    

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()

    # Verify that we are using the proper version and that the BFD
    # daemon exists.
    for router in router_list.values():
        # Check for Version
        if router.has_version('<', '5.1'):
            tgen.set_error('Unsupported FRR version')
            break

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    # This function tears down the whole topology.
    tgen.stop_topology()

# step 1 : load base config , check the policy state
def test_sbfd_before_check():
    "Assert that policy state before sbfd config."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.net['r1']

# 5a3c0fb637b9(config-sr-te-policy)# do show sr-te policy name PL1 detail 

# Endpoint: 3001::6  Color: 100  Name: PL1  BSID: -  Status: Active
#     Preference: 100  ActiveMembers: 2  Status: UP
#        Candidate Name: CP1  Type: explicit  Segment-List: SL1  Weight: 1  BindingBFD: -  Status: UP
#        Candidate Name: CP2  Type: explicit  Segment-List: SL2  Weight: 1  BindingBFD: -  Status: UP
#     Preference: 200  ActiveMembers: 1  Status: UP
#        Candidate Name: CP3  Type: explicit  Segment-List: SL3  Weight: 1  BindingBFD: -  Status: UP
#   * Preference: 300  ActiveMembers: 1  Status: UP
#        Candidate Name: CP4  Type: explicit  Segment-List: SL4  Weight: 1  BindingBFD: -  Status: UP

    show_policy_check(r1, 'PL1', 'Active', '100', 'UP', 'CP1', 'UP')
    show_policy_check(r1, 'PL1', 'Active', '100', 'UP', 'CP2', 'UP')
    show_policy_check(r1, 'PL1', 'Active', '200', 'UP', 'CP3', 'UP')
    show_policy_check(r1, 'PL1', 'Active', '200', 'UP', 'CP4', 'UP')
    show_policy_selected_check(r1, 'PL1', 'Active', '300')

# step 2 : config sbfd echo and check sbfd statue
def test_sbfd_config_check():
    "Assert that config sbfd and check bfd and policy status."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    # config sbfd
    r1 = tgen.net['r1']
    r1.cmd("vtysh -c 'config t' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 100 endpoint 3001::6' -c 'sbfd echo source-address 3001::1'")

    logger.info('waiting 3 sec ... for sbfd up')
    time.sleep(3)
    
    show_bfd_specific_check(r1, 'SL1', 'up')
    show_bfd_specific_check(r1, 'SL2', 'up')
    show_bfd_specific_check(r1, 'SL3', 'up')
    show_bfd_specific_check(r1, 'SL4', 'up')

    show_policy_selected_check(r1, 'PL1', 'Active', '300')

# step 3 : shutdown if and no shutdown if then check bfd and policy status
def test_sbfd_updown_interface():
    "Assert that updown interface then check bfd and policy status."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.net['r1']
    r4 = tgen.net['r4']
    r5 = tgen.net['r5']
    
    # shutdown interface
    r5.cmd("vtysh -c 'config t' -c 'interface r5-eth1' -c 'shutdown'")
    time.sleep(5)
    show_bfd_specific_check(r1, 'SL3', 'up')
    show_bfd_specific_check(r1, 'SL4', 'down')
    show_policy_check(r1, 'PL1', 'Active', '300', 'DOWN', 'CP4', 'DOWN')
    show_policy_selected_check(r1, 'PL1', 'Active', '200')

    # shutdown interface
    r4.cmd("vtysh -c 'config t' -c 'interface r4-eth1' -c 'shutdown'")
    time.sleep(5)
    show_bfd_specific_check(r1, 'SL1', 'up')
    show_bfd_specific_check(r1, 'SL2', 'down')
    show_policy_check(r1, 'PL1', 'Active', '100', 'UP', 'CP1', 'UP')
    show_policy_selected_check(r1, 'PL1', 'Active', '200')

    # no shutdown interface
    r5.cmd("vtysh -c 'config t' -c 'interface r5-eth1' -c 'no shutdown'")
    time.sleep(5)
    show_bfd_specific_check(r1, 'SL3', 'up')
    show_bfd_specific_check(r1, 'SL4', 'up')
    show_policy_check(r1, 'PL1', 'Active', '300', 'UP', 'CP4', 'UP')
    show_policy_selected_check(r1, 'PL1', 'Active', '300')
    

# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
