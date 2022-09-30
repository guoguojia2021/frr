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
import functools
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# Required to instantiate the topology builder class.
from mininet.topo import Topo
from mininet.net import Mininet


"""
test_zebra_srv6vpn_topo.py:

 +----+----+        +----+----+  
 |         |        |         |
 |   R1    |   1    |   RT2   | 
 |         +--------+         |  
 |         |        |         | 
 +----+----+        +----+----+ 
 
"""

def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)

class Topology(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"

        tgen = get_topogen(self)
        tgen.add_router("r1")
        tgen.add_router("r2")

        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s3")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s4")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s5")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        # tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth0", "eth0")
        # tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth1", "eth1")
        # tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth2", "eth2")
        # tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth3", "eth3")
        # tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth4", "eth4")
        # tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth5", "eth5")

def setup_module(mod):
    result = required_linux_kernel_version("4.19")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(Topology, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in tgen.routers().items():
        # router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))

        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP,
            os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        )
    
        router.load_config(
            TopoRouter.RD_STATIC,
            os.path.join(CWD, '{}/staticd.conf'.format(rname))
        )

    tgen.gears["r1"].run("ip link add Vrf1 type vrf table 1")
    tgen.gears["r1"].run("ip link set Vrf1 up")
    tgen.gears["r1"].run("ip link add Vrf2 type vrf table 2")
    tgen.gears["r1"].run("ip link set Vrf2 up")
    tgen.gears["r1"].run("ip link set eth1 master Vrf1")
    tgen.gears["r1"].run("ip link set eth2 master Vrf2")


    tgen.gears["r2"].run("ip link add Vrf1 type vrf table 1")
    tgen.gears["r2"].run("ip link set Vrf1 up")
    tgen.gears["r2"].run("ip link add Vrf2 type vrf table 2")
    tgen.gears["r2"].run("ip link set Vrf2 up")
    tgen.gears["r2"].run("ip link set eth1 master Vrf1")
    tgen.gears["r2"].run("ip link set eth2 master Vrf2")
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    # This function tears down the whole topology.
    tgen.stop_topology()


def test_srv6_locator():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears['r1']
    r2 = tgen.gears['r2']

    def _check_srv6_locator(router, expected_locator_file):
        logger.info("checking zebra locator status")
        output = json.loads(router.vtysh_cmd("show segment-routing srv6 locator json"))
        expected = open_json_file("{}/{}/{}".format(CWD, router.name, expected_locator_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_locator(router, expected_file):
        func = functools.partial(_check_srv6_locator, router, expected_file)
        success, result = topotest.run_and_expect(func, None, count=5, wait=0.5)
        assert result is None, 'Failed'

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for Locator ")
    check_srv6_locator(r1, "expected_locators1.json")
    check_srv6_locator(r2, "expected_locators1.json")

def test_srv6_vpn():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    # r1 = tgen.gears['r1']
    r2 = tgen.gears['r2']

    def _check_srv6_vpn(router, expected_file):
        logger.info("checking zebra ipv6 vpn infos")
        output = json.loads(router.vtysh_cmd("show bgp ipv6 vpn json"))
        expected = open_json_file("{}/{}/{}".format(CWD, router.name, expected_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_vpn(router, expected_file):
        func = functools.partial(_check_srv6_vpn, router, expected_file)
        success, result = topotest.run_and_expect(func, None, count=5, wait=0.5)
        assert result is None, 'Failed'

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.

    logger.info("Test for ipv6 vpn ")
    # check_srv6_vpn(r1, "expected_ipv6vpn.json")
    check_srv6_vpn(r2, "expected_ipv6vpn.json")


def test_srv6_uni():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears['r1']
    r2 = tgen.gears['r2']

    def _check_srv6_uni(router, vrf, expected_file):
        logger.info("checking zebra ipv6 uni infos")
        output = json.loads(router.vtysh_cmd("show bgp vrf {} ipv6 uni json".format(vrf)))
        expected = open_json_file("{}/{}/{}".format(CWD, router.name, expected_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_uni(router, vrf, expected_file):
        func = functools.partial(_check_srv6_uni, router, vrf, expected_file)
        success, result = topotest.run_and_expect(func, None, count=5, wait=0.5)
        assert result is None, 'Failed'

    logger.info("Test for uni ")
    check_srv6_uni(r1, 'Vrf1', "expected_uni.json")
    check_srv6_uni(r2, 'Vrf1', "expected_uni.json")

def test_srv6_vpn_route():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears['r2']

    def _check_srv6_vpn_route(router, vrf, expected_file):
        logger.info("checking zebra vpn route infos")
        output = json.loads(router.vtysh_cmd("show ipv6 route vrf {} json".format(vrf)))
        expected = open_json_file("{}/{}/{}".format(CWD, router.name, expected_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_vpn_route(router, vrf, expected_file):
        func = functools.partial(_check_srv6_vpn_route, router, vrf, expected_file)
        success, result = topotest.run_and_expect(func, None, count=5, wait=0.5)
        assert result is None, 'Failed'

    logger.info("Test for vpn route ")
    check_srv6_vpn_route(r2, 'Vrf1', "expected_vpn_route.json")

def test_srv6_route():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears['r1']
    r2 = tgen.gears['r2']

    def _check_srv6_route(router, expected_file):
        logger.info("checking zebra route infos")
        output = json.loads(router.vtysh_cmd("show ipv6 route json"))
        expected = open_json_file("{}/{}/{}".format(CWD, router.name, expected_file))
        return topotest.json_cmp(output, expected)

    def check_srv6_route(router, expected_file):
        func = functools.partial(_check_srv6_route, router, expected_file)
        success, result = topotest.run_and_expect(func, None, count=5, wait=0.5)
        assert result is None, 'Failed'

    logger.info("Test for vpn route ")
    check_srv6_route(r1,  "expected_route.json")
    check_srv6_route(r2,  "expected_route.json")

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
