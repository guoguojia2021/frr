#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018, LabN Consulting, L.L.C.
# Authored by Lou Berger <lberger@labn.net>
#

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version
from lib.checkping import check_ping

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r"""
    ┌──────┐                  ┌──────┐                   ┌──────┐
    │  CE1 ┼─┐            ┌───┤  P1  ┼──┐              ┌─┤  CE3 │
    └──────┘ │ Vrf1       │   └───|──┘  │              │ └──────┘
             │ ┌──────┐   │       |     │    ┌──────┐  │ Vrf1        
             ┼─┼  PE1 ┼───┤       |     ┼────┤  PE2 ┼──┤         
             │ └──────┘   │       |     │    └──────┘  │ Vrf2        
    ┌──────┐ │ Vrf2       │   ┌───|──┐  │              │ ┌──────┐
    │  CE2 ┼─┘            └───┤  P2  ┼──┘              └─┼  CE4 │
    └──────┘                  └──────┘                   └──────┘
    """
    tgen.add_router("pe1")
    tgen.add_router("pe2")
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")
    tgen.add_router("p1")
    tgen.add_router("p2")

    tgen.add_link(tgen.gears["pe1"], tgen.gears["p1"], "eth1", "eth1")
    tgen.add_link(tgen.gears["pe1"], tgen.gears["p2"], "eth2", "eth1")
    tgen.add_link(tgen.gears["pe2"], tgen.gears["p1"], "eth1", "eth2")
    tgen.add_link(tgen.gears["pe2"], tgen.gears["p2"], "eth2", "eth2")
    tgen.add_link(tgen.gears["ce1"], tgen.gears["pe1"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["pe1"], "eth0", "eth4")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["pe2"], "eth0", "eth3")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["pe2"], "eth0", "eth4")
    tgen.add_link(tgen.gears["p1"], tgen.gears["p2"], "eth3", "eth3")

def setup_module(mod):
    result = required_linux_kernel_version("5.4.0")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in tgen.routers().items():
        if os.path.exists("{}/{}/setup.sh".format(CWD, rname)):
            router.run("/bin/bash {}/{}/setup.sh".format(CWD, rname))
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.gears["pe1"].run("ip link add vrf1 type vrf table 1")
    tgen.gears["pe1"].run("ip link set vrf1 up")
    tgen.gears["pe1"].run("ip link add vrf2 type vrf table 2")
    tgen.gears["pe1"].run("ip link set vrf2 up")
    tgen.gears["pe1"].run("ip link set eth3 master vrf1")
    tgen.gears["pe1"].run("ip link set eth4 master vrf2")

    tgen.gears["pe2"].run("ip link add vrf1 type vrf table 1")
    tgen.gears["pe2"].run("ip link set vrf1 up")
    tgen.gears["pe2"].run("ip link add vrf2 type vrf table 2")
    tgen.gears["pe2"].run("ip link set vrf2 up")
    tgen.gears["pe2"].run("ip link set eth3 master vrf1")
    tgen.gears["pe2"].run("ip link set eth4 master vrf2")
    tgen.start_router()

    # FOR DEVELOPER:
    # If you want to stop some specific line and start interactive shell,
    # please use tgen.mininet_cli() to start it.


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def check_rib(name, cmd, expected_file):
    def _check(name, cmd, expected_file):
        logger.info("polling")
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    tgen = get_topogen()
    func = functools.partial(_check, name, cmd, expected_file)
    _, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
    assert result is None, "Failed"


def test_locator_recreate():
    import pdb; pdb.set_trace()
    check_rib("pe1", "show bgp ipv4 vpn json", "r1/vpnv4_rib_locator_recreated.json")
    check_rib("pe2", "show bgp ipv6 vpn json", "r2/vpnv6_rib_locator_recreated.json")



if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
