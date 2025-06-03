#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_srv6_sid_explicit.py
#
# Copyright (c) 2025 by
# Alibaba Inc, Yuqing Zhao <galadriel.zyq@alibaba-inc.com>
#

"""
test_bgp_bestpath_nexthop_resolved_tunnel.py:

Verify the behavior of the 'bgp bestpath nexthop-resolved tunnel' command.
Whether a route is valid generally depends on the validity of ip nexthop,
while sometimes we do wanna keep the route as valid when it only has a tunnel nexthop.
That's what this command controls.

LOGIC TABLE:
·-----------------------------------------------------------------------------------------·
|  Relay-Nexthop(ip) | Relay-Nexthop(tunnel) | bestpath nexthop-resolved tunnel |  VALID  |
|-----------------------------------------------------------------------------------------|
|          0         |          0            |              0 or 1              |    0    |
|--------------------|-----------------------|----------------------------------|---------|
|          1         |          1            |              0 or 1              |    1    |
|--------------------|-----------------------|----------------------------------|---------|
|          1         |          0            |              0 or 1              |    1    |
|--------------------|-----------------------|----------------------------------|---------|
|          0         |          1            |                0                 |    0    |
|--------------------|-----------------------|----------------------------------|---------|
|          0         |          1            |                1                 |    1    |
·-----------------------------------------------------------------------------------------·
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

#pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import required_linux_kernel_version
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.esr]


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    tgen.add_router("c11")
    tgen.add_router("c12")
    tgen.add_router("c21")
    tgen.add_router("c22")
    tgen.add_router("c31")
    tgen.add_router("c32")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth10", "eth10")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "eth1", "eth10")
    tgen.add_link(tgen.gears["r1"], tgen.gears["c11"], "eth2", "eth10")
    tgen.add_link(tgen.gears["r1"], tgen.gears["c12"], "eth3", "eth10")
    tgen.add_link(tgen.gears["r2"], tgen.gears["c21"], "eth1", "eth10")
    tgen.add_link(tgen.gears["r2"], tgen.gears["c22"], "eth2", "eth10")
    tgen.add_link(tgen.gears["r3"], tgen.gears["c31"], "eth1", "eth10")
    tgen.add_link(tgen.gears["r3"], tgen.gears["c32"], "eth2", "eth10")


def setup_module(mod):
    result = required_linux_kernel_version("5.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)

    frrdir = tgen.config.get(tgen.CONFIG_SECTION, "frrdir")
    if not os.path.isfile(os.path.join(frrdir, "pathd")):
        pytest.skip("pathd daemon wasn't built in:" + frrdir)

    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PATH, os.path.join(CWD, "{}/pathd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.gears["r1"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r1"].run("ip link set vrf10 up")
    tgen.gears["r1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r1"].run("ip link set vrf20 up")
    tgen.gears["r1"].run("ip link set eth2 master vrf10")
    tgen.gears["r1"].run("ip link set eth3 master vrf20")

    tgen.gears["r2"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r2"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r2"].run("ip link set vrf10 up")
    tgen.gears["r2"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r2"].run("ip link set vrf20 up")
    tgen.gears["r2"].run("ip link set eth1 master vrf10")
    tgen.gears["r2"].run("ip link set eth2 master vrf20")

    tgen.gears["r3"].run("sysctl net.vrf.strict_mode=1")
    tgen.gears["r3"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["r3"].run("ip link set vrf10 up")
    tgen.gears["r3"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["r3"].run("ip link set vrf20 up")
    tgen.gears["r3"].run("ip link set eth1 master vrf10")
    tgen.gears["r3"].run("ip link set eth2 master vrf20")

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


# We expect test to track the change between different states,
# and being adapted to multi-thread processing.
# So we write the cases as an integrated whole.
def test_bgp_bestpath_nexthop_resolved_tunnel():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    router3 = tgen.gears["r3"]


    # helper function, check state of target vpn route
    def _check_state(router, expected_route_file):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 192.168.2.0/24 json"))
        expected = open_json_file("{}/{}".format(CWD, expected_route_file))
        return topotest.json_cmp(output, expected)


    # 1st case,
    # check the original state with both valid ip and tunnel nexthop,
    # no bgp bestpath nexthop-resolved tunnel configuration,
    # route should be valid
    def case1_original_state(router, expected_file):
        logger.info("--------Case 1 begins----ip(1)--tunnel(1)--conf(0)--valid(1)--------")
        # Nothing to do, check state directly
        logger.info("BGP vpn route should be valid, checking ...")
        func = functools.partial(_check_state, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"


    # 2nd case, set ip nexthop invalid,
    # we have tunnel nexthop but with invalid ip nexthop
    # no bgp bestpath nexthop-resolved tunnel configuration,
    # valid -> invalid
    def case2_invalid_ip_with_tunnel_no_conf(router, expected_file):
        logger.info("--------Case 2 begins----ip(1->0)--tunnel(1)--conf(0)--valid(1->0)--------")
        # change ip nexthop invalid
        router.vtysh_cmd(
            """
            configure terminal
             no ipv6 route 2001:db8:12::/64 2001:db8:13::1
            """
        )
        logger.info("BGP vpn route should become invalid, checking ...")
        func = functools.partial(_check_state, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"


    # 3rd case, configure bgp bestpath nexthop-resolved tunnel,
    # we have tunnel nexthop but with invalid ip nexthop,
    # with bgp bestpath nexthop-resolved tunnel configuration,
    # invalid -> valid
    def case3_invalid_ip_with_tunnel_with_conf(router, expected_file):
        logger.info("--------Case 3 begins----ip(0)--tunnel(1)--conf(0->1)--valid(0->1)--------")
        # configure bgp bestpath nexthop-resolved tunnel
        router.vtysh_cmd(
            """
            configure terminal
             router bgp 65001
              bgp bestpath nexthop-resolved tunnel
            """
        )
        logger.info("BGP vpn route should become valid, checking ...")
        func = functools.partial(_check_state, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"


    # 4th case, remove tunnel nexthop,
    # invalid ip nexthop and no tunnel nexthop,
    # with bgp bestpath nexthop-resolved tunnel configuration,
    # valid -> invalid
    def case4_invalid_ip_no_tunnel_with_conf(router, expected_file):
        logger.info("--------Case 4 begins----ip(0)--tunnel(1->0)--conf(1)--valid(1->0)--------")
        # remove tunnel nexthop
        router.vtysh_cmd(
            """
            configure terminal
             segment-routing
              traffic-eng
               no policy color 2 endpoint 2001:db8:12::2
            """
        )
        logger.info("BGP vpn route should become invalid, checking ...")
        func = functools.partial(_check_state, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"


    # 5th case, set ip nexthop valid,
    # we have valid ip nexthop but no tunnel nexthop,
    # with bgp bestpath nexthop-resolved tunnel configuration,
    # invalid -> valid
    def case5_valid_ip_no_tunnel_with_conf(router, expected_file):
        logger.info("--------Case 5 begins----ip(0->1)--tunnel(0)--conf(1)--valid(0->1)--------")
        # set ip nexthop valid again
        router.vtysh_cmd(
            """
            configure terminal
             ipv6 route 2001:db8:12::/64 2001:db8:13::1
            """
        )
        logger.info("BGP vpn route should become valid, checking ...")
        func = functools.partial(_check_state, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"


    # 6th case, remove bgp bestpath nexthop-resolved tunnel configuration,
    # we have valid ip nexthop but no tunnel nexthop,
    # no bgp bestpath nexthop-resolved tunnel configuration
    # valid
    def case6_valid_ip_no_tunnel_no_conf(router, expected_file):
        logger.info("--------Case 6 begins----ip(1)--tunnel(0)--conf(1->0)--valid(1)--------")
        # remove bgp bestpath nexthop-resolved
        router.vtysh_cmd(
            """
            configure terminal
             router bgp 65001
              no bgp bestpath nexthop-resolved tunnel
            """
        )
        logger.info("BGP vpn route should be valid, checking ...")
        func = functools.partial(_check_state, router, expected_file)
        _, result = topotest.run_and_expect(func, None, count=15, wait=1)
        assert result is None, "Failed"


    # Test begins here
    case1_original_state(router3, "case1_original_state_expected.json")
    case2_invalid_ip_with_tunnel_no_conf(router3, "case2_invalid_ip_with_tunnel_no_conf_expected.json")
    case3_invalid_ip_with_tunnel_with_conf(router3, "case3_invalid_ip_with_tunnel_with_conf_expected.json")
    case4_invalid_ip_no_tunnel_with_conf(router3, "case4_invalid_ip_no_tunnel_with_conf_expected.json")
    case5_valid_ip_no_tunnel_with_conf(router3, "case5_valid_ip_no_tunnel_with_conf_expected.json")
    case6_valid_ip_no_tunnel_no_conf(router3, "case6_valid_ip_no_tunnel_no_conf_expected.json")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))