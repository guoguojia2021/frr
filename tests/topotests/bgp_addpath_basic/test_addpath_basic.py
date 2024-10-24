#!/usr/bin/env python

# Copyright (c) 2023 by
# Lingyu Zhang <hanyu.zly@alibaba-inc.com>
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
Test if AddPath RX direction is not negotiated via AddPath capability.
"""


"""
topology:
      +----------------------+   
      |         r2           |   
      |       2.2.2.2        |           
      | fd00:0:200:171::/128 |   
      +----------------------+   
           12.1.1.1| eth1   
                    |            
                     |           
          12.1.1.2/24 | eth1   
                    +----------------------+
                    |         r1           |
                    |       1.1.1.1        |                              RR router
                    |                      |
                    +----------------------+
          13.1.1.2/24 | eth2          eth3|14.1.1.2/24
                 ____/                    \____
                /                              \
                 |                              |
                  \                              |
                   \                             \
        13.1.1.1/24 | eth2                  eth3 | 14.1.1.1/24
      +---------+----------+         +----------+-----------+
      |       r3           |         |          r4          | 
      |     3.3.3.3        |         |       4.4.4.4        |               
      |                    |         |                      |
      +----------+---------+         +------------+---------+       
        15.1.1.1 |eth4                      16.1.1.1 | eth4    
                  /                              /
                |                               |
                |                               |
 15.1.1.2 eth4  |                               |  16.1.1.2 eth4
        +-------+-------+               +-------+-------+
        |  peer1        |               |  peer2        |
        |  5.5.5.5      |               |  6.6.6.6      |
        +---------------+               +---------------+
"""
import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd, pytest.mark.esr]


def build_topo(tgen):
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    peer1 = tgen.add_exabgp_peer("peer1", ip="15.1.1.2", defaultRoute="via 15.1.1.1")
    peer2 = tgen.add_exabgp_peer("peer2", ip="16.1.1.2", defaultRoute="via 16.1.1.1")

    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"], "eth1", "eth1")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r3"], "eth2", "eth2")
    tgen.add_link(tgen.gears["r1"], tgen.gears["r4"], "eth3", "eth3")
    tgen.add_link(tgen.gears["r3"], tgen.gears["peer1"], "eth4", "eth1")
    tgen.add_link(tgen.gears["r4"], tgen.gears["peer2"], "eth4", "eth2")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()

    # Start ExaBGP
    peer1 = tgen.gears["peer1"]
    peer1.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))

    peer2 = tgen.gears["peer2"]
    peer2.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

def check_bgp_routes(router, neighbor, expected_count):
    output = json.loads(router.vtysh_cmd(f"show bgp ipv4 unicast neighbors {neighbor} received-routes json"))
    actual_count = len(output.get("receivedRoutes", {}))
    return actual_count == expected_count

def test_bgp_addpath_basic():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step(
        "Check if r1 advertised only 1 paths to r2 (without addpath-tx-all-paths)."
    )

    def check_bgp_advertised_routes(router):
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 12.1.1.1 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "1.1.1.1/32": {
                    "addrPrefix": "1.1.1.1",
                    "prefixLen": 32,
                },
            },
            "totalPrefixCounter": 1,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_bgp_advertised_routes, r1)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "BGP peer advertise not working."

    step("Check if AddPath TX is enabled on r1 and we receive 2 paths.")

    def _bgp_addpath_enable(router):
        router.vtysh_cmd(
            "conf t\nrouter bgp 100\naddress-family ipv4\nneighbor 12.1.1.1 addpath-tx-all-paths"
        )
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 12.1.1.1 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "1.1.1.1/32": {
                    "addrPrefix": "1.1.1.1",
                    "prefixLen": 32,
                },
            },
            "totalPrefixCounter": 2,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_addpath_enable, r1)
    success, result = topotest.run_and_expect(test_func, None, count=6, wait=10)
    assert result is None, "AddPath TX not working"

    step("Disable AddPath TX on r1 and check again.")

    def _disable_addpath(router):
        router.vtysh_cmd(
            "conf t\nrouter bgp 100\naddress-family ipv4 unicast\nno neighbor 12.1.1.1 addpath-tx-all-paths"
        )
        output = json.loads(
            router.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 12.1.1.1 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "1.1.1.1/32": {
                    "addrPrefix": "1.1.1.1",
                    "prefixLen": 32,
                },
            },
            "totalPrefixCounter": 1,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_disable_addpath, r1)
    success, result = topotest.run_and_expect(test_func, None, count=6, wait=10)
    assert result is None, "Disabling AddPath TX not working"

"""
def test_bgp_addpath_neigh_config():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    step("Configure AddPath on r1 and non-AddPath on r3. Check negotiation status.")

    def configure_mixed_addpath(router1, router2):
        router1.vtysh_cmd(
            "conf t\nrouter bgp 100\naddress-family ipv4 unicast\nneighbor 12.1.1.1 addpath-tx-all-paths\n"
        )
        router2.vtysh_cmd(
            "conf t\nrouter bgp 200\naddress-family ipv4 unicast\nneighbor 12.1.1.2 disable-addpath-rx\n"
        )
        output1 = json.loads(router1.vtysh_cmd("show bgp ipv4 neighbors 12.1.1.1 json"))
        output2 = json.loads(router2.vtysh_cmd("show bgp ipv4 neighbors 12.1.1.2 json"))
        return output1['neighborCapabilities']['addPath']['ipv4Unicast']['txAdvertised'] and \
               not output2['neighborCapabilities']['addPath']['ipv4Unicast']['txReceived']

    test_func = functools.partial(configure_mixed_addpath, r1, r3)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert success, "Mixed AddPath capability configuration failed."
"""
if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
