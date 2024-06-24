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
                    |         r1           |
                    |       1.1.1.1        |                              RR router
                    |                      |
                    +----------------------+
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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")

def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_PATH, os.path.join(CWD, "{}/pathd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_static_route_srte():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step(
        "Configure an IPv4 route with an IPv6 next-hop and set the color. Then, check the route status."
    )

    def check_static_ipv4_routes(router):
        output = json.loads(
            router.vtysh_cmd(
                "show ip route 10.10.10.10/32 json"
            )
        )
        expected = {
                "10.10.10.10/32": [{
                    "prefix": "10.10.10.10/32",
                    "protocol": "static",
                    "selected":True,
                    "nexthops":[
                    {
                        "ip":"1000::178",
                        "afi":"ipv6",
                        "resolver":True,
                        "active":True,
                        "weight":1,
                        "srteColor":1,
                        "segment-list":"a"
                    },
                    {
                        "ip":"1000::178",
                        "afi":"ipv6",
                        "resolver":True,
                        "active":True,
                        "weight":1,
                        "srteColor":1,
                        "segment-list":"c"
                    }
                    ]
                }
                ]
            }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_static_ipv4_routes, r1)
    success, result = topotest.run_and_expect(test_func, None, count=6, wait=10)
    assert result is None, "Static ipv4 route with color not working"

    step(
        "Configure an IPv6 route with an IPv6 next-hop and set the color. Then, check the route status."
    )
    def check_static_ipv6_routes(router):
        output = json.loads(
            router.vtysh_cmd(
                "show ipv6 route 1111::11/128 json"
            )
        )
        expected = {
            "1111::11/128":[
                {
                "prefix":"1111::11/128",
                "prefixLen":128,
                "protocol":"static",
                "vrfId":0,
                "vrfName":"Default",
                "selected":True,
                "destSelected":True,
                "distance":1,
                "metric":0,
                "vrf_group":0,
                "installed":True,
                "internalNextHopNum":3,
                "internalNextHopActiveNum":3,
                "nexthops":[
                    {
                    "ip":"2000::178",
                    "afi":"ipv6",
                    "active":True,
                    "recursive":True,
                    "weight":1,
                    "srteColor":2,
                    "segment-list":""
                    },
                    {
                    "fib":True,
                    "ip":"2000::178",
                    "afi":"ipv6",
                    "resolver":True,
                    "active":True,
                    "weight":1,
                    "srteColor":2,
                    "segment-list":"b"
                    },
                    {
                    "fib":True,
                    "ip":"2000::178",
                    "afi":"ipv6",
                    "resolver":True,
                    "active":True,
                    "weight":1,
                    "srteColor":2,
                    "segment-list":"d"
                    }
                ]
                }
            ]
            }


        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_static_ipv6_routes, r1)
    success, result = topotest.run_and_expect(test_func, None, count=6, wait=10)
    assert result is None, "Static ipv6 route with color not working"

    step(
        "Configure routes with the same prefix but with different IPv6 next-hops, iterating to two different SR-TEs and forming ECMP. Check the route iteration status."
    )
    def check_static_ipv4_routes_ecmp(router):
        router.vtysh_cmd(
            "conf t\nip route 10.10.10.10/32 2000::178 color 2\n"
        )
        output = json.loads(
            router.vtysh_cmd(
                "show ip route 10.10.10.10/32 json"
            )
        )
        expected = {
            "10.10.10.10/32":[
                {
                "prefix":"10.10.10.10/32",
                "prefixLen":32,
                "protocol":"static",
                "vrfId":0,
                "vrfName":"Default",
                "selected":True,
                "destSelected":True,
                "distance":1,
                "metric":0,
                "installed":True,
                "internalNextHopNum":6,
                "internalNextHopActiveNum":6,
                "nexthops":[
                    {
                    "ip":"1000::178",
                    "afi":"ipv6",
                    "active":True,
                    "recursive":True,
                    "weight":1,
                    "srteColor":1,
                    "segment-list":""
                    },
                    {
                    "fib":True,
                    "ip":"1000::178",
                    "afi":"ipv6",
                    "resolver":True,
                    "active":True,
                    "weight":1,
                    "srteColor":1,
                    "segment-list":"a"
                    },
                    {
                    "fib":True,
                    "ip":"1000::178",
                    "afi":"ipv6",
                    "resolver":True,
                    "active":True,
                    "weight":1,
                    "srteColor":1,
                    "segment-list":"c"
                    },
                    {
                    "ip":"2000::178",
                    "afi":"ipv6",
                    "active":True,
                    "recursive":True,
                    "weight":1,
                    "srteColor":2,
                    "segment-list":""
                    },
                    {
                    "fib":True,
                    "ip":"2000::178",
                    "afi":"ipv6",
                    "resolver":True,
                    "active":True,
                    "weight":1,
                    "srteColor":2,
                    "segment-list":"b"
                    },
                    {
                    "fib":True,
                    "ip":"2000::178",
                    "afi":"ipv6",
                    "resolver":True,
                    "active":True,
                    "weight":1,
                    "srteColor":2,
                    "segment-list":"d"
                    }
                ]
                }
            ]
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_static_ipv4_routes_ecmp, r1)
    success, result = topotest.run_and_expect(test_func, None, count=6, wait=10)
    assert result is None, "Static ipv4 route with color ecmp not working"

    step(
        "Configure routes with the same prefix and same nexthop but with different color, iterating to two different SR-TEs and forming ECMP. Check the route iteration status."
    )
    def check_no_static_ipv4_routes_color(router):
        router.vtysh_cmd(
            "conf t\nno ip route 10.10.10.10/32 1000::178 color 1\n"
        )
        output = json.loads(
            router.vtysh_cmd(
                "show ip route 10.10.10.10/32 json"
            )
        )
        expected = {
          "10.10.10.10/32":[
            {
              "prefix":"10.10.10.10/32",
              "prefixLen":32,
              "protocol":"static",
              "vrfId":0,
              "vrfName":"Default",
              "selected":True,
              "destSelected":True,
              "distance":1,
              "metric":0,
              "vrf_group":0,
              "installed":True,
              "table":254,
              "internalNextHopNum":3,
              "internalNextHopActiveNum":3,
              "nexthops":[
                {
                  "ip":"2000::178",
                  "afi":"ipv6",
                  "active":True,
                  "recursive":True,
                  "weight":1,
                  "srteColor":2,
                  "segment-list":""
                },
                {
                  "fib":True,
                  "ip":"2000::178",
                  "afi":"ipv6",
                  "resolver":True,
                  "active":True,
                  "weight":1,
                  "srteColor":2,
                  "segment-list":"b"
                },
                {
                  "fib":True,
                  "ip":"2000::178",
                  "afi":"ipv6",
                  "resolver":True,
                  "active":True,
                  "weight":1,
                  "srteColor":2,
                  "segment-list":"d"
                }
              ]
            }
          ]
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_no_static_ipv4_routes_color, r1)
    success, result = topotest.run_and_expect(test_func, None, count=6, wait=10)
    assert result is None, "Delete Static ipv4 route with color not working"
if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
