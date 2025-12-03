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
      |         ce3          |   
      |       2.2.2.2        |           
      | fd00:0:200:171::/128 |   
      +----------------------+   
           162.0.1.2| ce3-eth0   
                    |            
                     |           
          162.0.1.1 | pe3-eth2   
                    +----------------------+
                    |         pe3          |
                    |       1.1.1.1        |
                    |                      |
                    +----------------------+
      2001:db8:12::1 | pe3-eth0  pe3-eth1|2001:db8:13::2
                 ____/                    \____
                /                              \
                 |                              |
                  \                              |
                   \                             \
     2001:db8:12::1 | pe1-eth1           pe2-eth1 | 2001:db8:13::1
      +---------+----------+         +----------+-----------+
      |       pe1          |         |         pe2          | 
      |     3.3.3.3        |         |       4.4.4.4        |               
      |                    |         |                      |
      +----------+---------+         +------------+---------+       
        192.0.1.2 |pe1-eth0                      16.1.1.1 | pe2-eth0   
                  /                              /
                |                               |
                |                               |
                | 192.0.1.1 ce1-eth0             |  16.1.1.2 ce2-eth0
        +-------+-------+               +-------+-------+
        |  peer1(ce1)   |               |  peer2(ce2)   |
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
    tgen.add_router("pe1")
    tgen.add_router("pe2")
    tgen.add_router("pe3")
    tgen.add_router("ce3")

    peer1 = tgen.add_exabgp_peer("peer1", ip="192.0.1.1", defaultRoute="via 192.0.1.2")
    peer2 = tgen.add_exabgp_peer("peer2", ip="16.1.1.2", defaultRoute="via 16.1.1.1")

    tgen.add_link(tgen.gears["pe1"], tgen.gears["pe3"], "pe1-eth1", "pe3-eth0")
    tgen.add_link(tgen.gears["pe2"], tgen.gears["pe3"], "pe2-eth1", "pe3-eth1")
    tgen.add_link(tgen.gears["pe3"], tgen.gears["ce3"], "ce3-eth0", "pe3-eth2")
    tgen.add_link(tgen.gears["pe1"], tgen.gears["peer1"], "pe1-eth0", "ce1-eth0")
    tgen.add_link(tgen.gears["pe2"], tgen.gears["peer2"], "pe2-eth0", "ce2-eth0")


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
        router.load_config(
            TopoRouter.RD_PATH, os.path.join(CWD, "{}/pathd.conf".format(rname))
        )

    tgen.gears["pe1"].run("ip link add vrf1 type vrf table 10")
    tgen.gears["pe1"].run("ip link set vrf1 up")    
    tgen.gears["pe1"].run("ip link set pe1-eth0 master vrf1")

    tgen.gears["pe2"].run("ip link add vrf1 type vrf table 10")
    tgen.gears["pe2"].run("ip link set vrf1 up")    
    tgen.gears["pe2"].run("ip link set pe2-eth0 master vrf1")

    tgen.gears["pe3"].run("ip link add vrf1 type vrf table 10")
    tgen.gears["pe3"].run("ip link set vrf1 up")    
    tgen.gears["pe3"].run("ip link set pe3-eth2 master vrf1")

    tgen.start_router()

    # Start ExaBGP
    peer1 = tgen.gears["peer1"]
    peer1.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))

    peer2 = tgen.gears["peer2"]
    peer2.start(os.path.join(CWD, "peer2"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_srv6_te():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["pe1"]
    pe2 = tgen.gears["pe2"]
    pe3 = tgen.gears["pe3"]

    step("Check basic BGP setup.")
    # check bgp neighbor state
    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn summary json"))
        expected = {
            "peers":{
                "2001:db8:12::1": {
                    "pfxRcd": 1,
                    "state": "Established"
                },
                "2001:db8:13::1": {
                    "pfxRcd": 1,
                    "state": "Established"
                },
            }
        }
        return topotest.json_cmp(output, expected)

    # Check r2 initial convergence in default table
    test_func = functools.partial(_bgp_converge, pe3)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed check basic BGP setup in "{}"'.format(pe3)

    step("Check bgp route status.")
    # check bgp route
    def _bgp_check_route(router):
        """
        检查 PE3 上关于 prefix 1.1.1.1 和 2.2.2.2 的 BGP 路由是否符合预期。
        如果任意一项不满足，则返回详细的比较结果；全部匹配则返回 None 表示成功。
        """

        # 检查第一个 prefix: 1.1.1.1
        output1 = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 1.1.1.1 json"))
        expected1 = {
            "1:1": {
                "prefix": "1.1.1.1/32",
                "paths": [
                    {
                        "aspath": {
                            "string": "100",
                            "segments": [{"type": "as-sequence", "list": [100]}],
                        },
                        "Relay-Nexthop(ip)": "if pe3-eth0",
                        "Relay-Nexthop(tunnel)": "srv6-tunnel:2001:db8:12::1|2(endpoint|color)",
                        "Relay-Nexthop(backup-tunnel)": "srv6-tunnel:2001:db8:12::1|1(endpoint|color)",
                        "extendedCommunity": {"string": "RT:1:1 Color:01:1 Color:01:2"},
                        "remoteLabel": 3,
                        "remoteSid": "fd00:201:2022:fff0:1::",
                    }
                ]
            }
        }

        result1 = topotest.json_cmp(output1, expected1)
        if result1 is not None:
            return f"Failed checking route 1.1.1.1:\n{result1}"

        # 检查第二个 prefix: 2.2.2.2
        output2 = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 2.2.2.2 json"))
        expected2 = {
            "2:2": {
                "prefix": "2.2.2.2/32",
                "paths": [
                    {
                        "aspath": {
                            "string": "100",
                            "segments": [{"type": "as-sequence", "list": [100]}],
                            "length": 1,
                        },
                        "Relay-Nexthop(ip)": "if pe3-eth1",
                        "valid": True,
                        "version": 1,
                        "extendedCommunity": {
                            "string": "RT:2:2 Color:00:1 Color:00:2"
                        },
                        "remoteLabel": 3,
                        "remoteSid": "fd00:201:2023:fff0:1::",
                    }
                ]
            }
        }

        result2 = topotest.json_cmp(output2, expected2)
        if result2 is not None:
            return f"Failed checking route 2.2.2.2:\n{result2}"

        # 所有检查都通过
        return None

    test_func = functools.partial(_bgp_check_route, pe3)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed check bgp route in "{}"'.format(pe3)

    step("modifation the color of the route, and check the sr-te status. Multi-color to single-color")
    def _bgp_checkout_route_1(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 1.1.1.1 json"))
        expected = {
            "1:1": {
                "prefix": "1.1.1.1/32",
                "paths": [
                    {
                        "aspath": {
                            "string": "100",
                            "segments": [{"type": "as-sequence", "list": [100]}],
                        },
                        "Relay-Nexthop(ip)": "if pe3-eth0",
                        "Relay-Nexthop(tunnel)": "srv6-tunnel:2001:db8:12::1|2(endpoint|color)",
                        "extendedCommunity": {"string": "RT:1:1 Color:01:2"},
                        "remoteLabel": 3,
                        "remoteSid": "fd00:201:2022:fff0:1::",
                    }
                ]
            }
        }
        return topotest.json_cmp(output, expected)

    pe1.vtysh_cmd(
        """
          configure terminal
            route-map setcolor permit 10
              set extcommunity color 1:2
        """
    )

    test_func = functools.partial(_bgp_checkout_route_1, pe3)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed check single-color in "{}"'.format(pe3)

    step("modifation the color of the route, and check the sr-te status. Single-color to Multi-color")
    def _bgp_checkout_route_2(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 1.1.1.1 json"))
        expected = {
            "1:1": {
                "prefix": "1.1.1.1/32",
                "paths": [
                    {
                        "aspath": {
                            "string": "100",
                            "segments": [{"type": "as-sequence", "list": [100]}],
                        },
                        "Relay-Nexthop(ip)": "if pe3-eth0",
                        "Relay-Nexthop(tunnel)": "srv6-tunnel:2001:db8:12::1|2(endpoint|color)",
                        "extendedCommunity": {"string": "RT:1:1 Color:01:2"},
                        "remoteLabel": 3,
                        "remoteSid": "fd00:201:2022:fff0:1::",
                    }
                ]
            }
        }
        return topotest.json_cmp(output, expected)

    pe1.vtysh_cmd(
        """
          configure terminal
            route-map setcolor permit 10
              set extcommunity color 1:1 1:2
        """
    )

    test_func = functools.partial(_bgp_checkout_route_2, pe3)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed check multi-color in "{}"'.format(pe3)

    step("modifation the color flag of the route, and check the sr-te status. Spefic-color to color-only")
    def _bgp_checkout_route_3(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 2.2.2.2 json"))
        expected = {
            "2:2": {
                "prefix": "2.2.2.2/32",
                "paths": [
                    {
                        "aspath": {
                            "string": "100",
                            "segments": [{"type": "as-sequence", "list": [100]}],
                        },
                        "Relay-Nexthop(ip)": "if pe3-eth1",
                        "extendedCommunity": {"string": "RT:2:2 Color:00:1 Color:00:2"},
                        "remoteLabel": 3,
                        "remoteSid": "fd00:201:2023:fff0:1::",
                    }
                ]
            }
        }
        
        # Check that output does not contain "Relay-Nexthop(tunnel)"
        output_str = str(output)
        if "Relay-Nexthop(tunnel)" in output_str:
            return f"Output contains forbidden string 'Relay-Nexthop(tunnel)'"
        
        # Check that all expected content (except Relay-Nexthop(tunnel) lines) is present
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_checkout_route_3, pe3)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed check spefic-color in "{}"'.format(pe3)

    pe2.vtysh_cmd(
        """
          configure terminal
            route-map setcolor permit 10
              set extcommunity color 1:1 1:2
        """
    )
    def _bgp_checkout_route_4(router):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 2.2.2.2 json"))
        expected = {
            "2:2": {
                "prefix": "2.2.2.2/32",
                "paths": [
                    {
                        "aspath": {
                            "string": "100",
                            "segments": [{"type": "as-sequence", "list": [100]}],
                        },
                        "Relay-Nexthop(ip)": "if pe3-eth1",
                        "Relay-Nexthop(tunnel)":"srv6-tunnel:2001:db8:13::1|2(endpoint|color)",
                        "Relay-Nexthop(backup-tunnel)":"srv6-tunnel:2001:db8:13::1|1(endpoint|color)",
                        "extendedCommunity": {"string": "RT:2:2 Color:01:1 Color:01:2"},
                        "remoteLabel": 3,
                        "remoteSid": "fd00:201:2023:fff0:1::",
                    }
                ]
            }
        }
        return topotest.json_cmp(output, expected)
    
    test_func = functools.partial(_bgp_checkout_route_4, pe3)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, 'Failed check color-only in "{}"'.format(pe3)

    step("Remove all color attributes and verify tunnel info is removed")
    def _bgp_check_no_color_route(router):
        # Remove color attributes
        pe2.vtysh_cmd(
            """
              configure terminal
                route-map setcolor permit 10
                  no set extcommunity color 1:1 1:2
            """
        )
        
        output = json.loads(router.vtysh_cmd("show bgp ipv4 vpn 2.2.2.2 json"))
        expected = {
            "2:2": {
                "prefix": "2.2.2.2/32",
                "paths": [
                    {
                        "aspath": {
                            "string": "100",
                            "segments": [{"type": "as-sequence", "list": [100]}],
                        },
                        "Relay-Nexthop(ip)": "if pe3-eth1",
                        # Should not have tunnel information when no color attributes
                        "extendedCommunity": {"string": "RT:2:2"},
                        "remoteLabel": 3,
                    }
                ]
            }
        }
        
        # Verify tunnel information is not present
        output_str = str(output)
        if "Relay-Nexthop(tunnel)" in output_str:
            return f"Output still contains tunnel info after removing color attributes: {output_str}"
        
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_no_color_route, pe3)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, 'Failed to verify removal of tunnel info in "{}"'.format(pe3)

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
