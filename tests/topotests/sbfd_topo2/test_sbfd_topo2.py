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

"""
test_sbfd_topo2.py:

     
 +----+----+        +----+----+        +----+----+
 |         |        |         |        |         | 
 |   RT1   |   1    |   RT2   |   1    |   RT3   |   
 |         +--------+         |--------|         |   
 |         |        |         |        |         |     
 +----+----+        +----+----+        +----+----+     
   
"""
# pytestmark = [pytest.mark.esr]

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
def build_topo(tgen):
    "Test topology builder"

    # This function only purpose is to define allocation and relationship
    # between routers, switches and hosts.
    #
    # Example
    #
    # Create 2 routers
    for routern in range(1, 4):
        tgen.add_router('r{}'.format(routern))

    # Create a switch with just one router connected to it to simulate a
    # empty network.
    switch = tgen.add_switch('s1')
    switch.add_link(tgen.gears['r1'])
    switch.add_link(tgen.gears['r2'])

    switch = tgen.add_switch('s2')
    switch.add_link(tgen.gears['r2'])
    switch.add_link(tgen.gears['r3'])

def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
    cmd1 = "sysctl -w net.ipv6.conf.all.seg6_enabled=1"
    cmd2 = "sysctl -w net.ipv6.conf.default.seg6_enabled=1"
    cmd3 = "sysctl -w net.ipv6.conf.{}-eth0.seg6_enabled=1"
    cmd4 = "sysctl -w net.ipv6.conf.{}-eth1.seg6_enabled=1"
    for rname, router in router_list.items():
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
        router.run(cmd1)
        router.run(cmd2)
        exec_cmd = cmd3.format(rname)
        router.run(exec_cmd)
        if rname == 'r2':
            exec_cmd = cmd4.format(rname)
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

    show_policy_check(r1, 'POLICY01', 'Active', '100', 'UP', 'CP1', 'UP')

# step 2 : config sbfd echo and check sbfd statue
def test_sbfd_config_check():
    "Assert that config sbfd and check bfd and policy status."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    # config sbfd
    r1 = tgen.net['r1']
    r1.cmd("vtysh -c 'config t' -c 'segment-routing' -c 'traffic-eng' -c 'policy color 100 endpoint 3001::3' -c 'sbfd echo source-address 3001::1'")

    logger.info('waiting 3 sec ... for sbfd up')
    time.sleep(3)
    
    show_bfd_check(r1, 'SL1', 'up', 'echo')
    show_policy_check(r1, 'POLICY01', 'Active', '100', 'UP', 'CP1', 'UP')

# step 3 : shutdown if and no shutdown if then check bfd and policy status
def test_sbfd_updown_interface():
    "Assert that updown interface then check bfd and policy status."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.net['r1']
    r2 = tgen.net['r2']
    
    # shutdown interface
    r2.cmd("vtysh -c 'config t' -c 'interface r2-eth0' -c 'shutdown'")
    time.sleep(5)
    show_bfd_check(r1, 'SL1', 'down', 'echo')
    show_policy_check(r1, 'POLICY01', 'Inactive', '100', 'DOWN', 'CP1', 'DOWN')
    
    # up interface
    r2.cmd("vtysh -c 'config t' -c 'interface r2-eth0' -c 'no shutdown'")
    time.sleep(5)
    show_bfd_check(r1, 'SL1', 'up', 'echo')
    show_policy_check(r1, 'POLICY01', 'Active', '100', 'UP', 'CP1', 'UP')
    

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
