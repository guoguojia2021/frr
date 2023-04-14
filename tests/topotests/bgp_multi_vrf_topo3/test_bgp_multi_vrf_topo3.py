#!/usr/bin/env python

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND VMWARE DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VMWARE BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Following tests are covered to test BGP Multi-VRF:

CHAOS_1:
    Do a shut and no shut on connecting interface of DUT,
    to see if all vrf instances clear their respective BGP tables
    during the interface down and restores when interface brought
kCHAOS_3:
    VRF leaking - next-hop interface is flapping.
CHAOS_5:
    VRF - VLANs - Routing Table ID - combination testcase
    on DUT.
CHAOS_9:
    Verify that all vrf instances fall back
    to backup path, if primary link goes down.
CHAOS_6:
    Restart BGPd daemon on DUT to check if all the
    routes in respective vrfs are reinstalled..
CHAOS_2:
    Delete a VRF instance from DUT and check if the routes get
    deleted from subsequent neighbour routers and appears again once VRF
    is re-added.
CHAOS_4:
    Verify that VRF names are locally significant
    to a router, and end to end connectivity depends on unique
    virtual circuits (using VLANs or separate physical interfaces).
CHAOS_8:
    Restart all FRR services (reboot DUT) to check if all
    the routes in respective vrfs are reinstalled.
"""

import os
import sys
import json
import time
import pytest
from copy import deepcopy
from time import sleep


# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from mininet.topo import Topo
from lib.topotest import iproute2_is_vrf_capable
from lib.common_config import (
    step,
    verify_rib,
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    create_route_maps,
    shutdown_bringup_interface,
    start_router_daemons,
    create_static_routes,
    create_vrf_cfg,
    create_interfaces_cfg,
    create_interface_in_kernel,
    get_frr_ipv6_linklocal,
    check_router_status,
    apply_raw_config,
    required_linux_kernel_version,
    kill_router_daemons,
    start_router_daemons,
    stop_router,
    start_router,
)

from lib.topolog import logger
from lib.bgp import clear_bgp, verify_bgp_rib, create_router_bgp, verify_bgp_convergence
from lib.topojson import build_config_from_json, build_topo_from_json


pytestmark = [pytest.mark.bgpd, pytest.mark.staticd, pytest.mark.esr]


# Reading the data from JSON File for topology creation
jsonFile = "{}/bgp_multi_vrf_topo2.json".format(CWD)

try:
    with open(jsonFile, "r") as topoJson:
        topo = json.load(topoJson)
except IOError:
    assert False, "Could not read file {}".format(jsonFile)

# Global variables
NETWORK1_1 = {"ipv4": "1.1.1.1/32", "ipv6": "1::1/128"}
NETWORK1_2 = {"ipv4": "1.1.1.2/32", "ipv6": "1::2/128"}
NETWORK2_1 = {"ipv4": "2.1.1.1/32", "ipv6": "2::1/128"}
NETWORK2_2 = {"ipv4": "2.1.1.2/32", "ipv6": "2::2/128"}
NETWORK3_1 = {"ipv4": "3.1.1.1/32", "ipv6": "3::1/128"}
NETWORK3_2 = {"ipv4": "3.1.1.2/32", "ipv6": "3::2/128"}
NETWORK4_1 = {"ipv4": "4.1.1.1/32", "ipv6": "4::1/128"}
NETWORK4_2 = {"ipv4": "4.1.1.2/32", "ipv6": "4::2/128"}
NETWORK9_1 = {"ipv4": "100.1.0.1/30", "ipv6": "100::1/126"}
NETWORK9_2 = {"ipv4": "100.1.0.2/30", "ipv6": "100::2/126"}

NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}

LOOPBACK_2 = {
    "ipv4": "20.20.20.20/32",
    "ipv6": "20::20:20/128",
    "ipv4_mask": "255.255.255.255",
    "ipv6_mask": None,
}

MAX_PATHS = 2
KEEPALIVETIMER = 1
HOLDDOWNTIMER = 3
PREFERRED_NEXT_HOP = ""


class CreateTopo(Topo):
    """
    Test BasicTopo - topology 1

    * `Topo`: Topology object
    """

    def build(self, *_args, **_opts):
        """Build function"""
        tgen = get_topogen(self)

        # Building topology from json file
        build_topo_from_json(tgen, topo)


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.14")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    # iproute2 needs to support VRFs for this suite to run.
    if not iproute2_is_vrf_capable():
        pytest.skip("Installed iproute2 version does not support VRFs")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    tgen = Topogen(CreateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global BGP_CONVERGENCE
    global ADDR_TYPES
    ADDR_TYPES = check_address_types()

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


#####################################################
#
#   Testcases
#
#####################################################

def test_vrf_vlan_routing_table_p1(request):
    """
    CHAOS_5:
    VRF - VLANs - Routing Table ID - combination testcase
    on DUT.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise unique prefixes(IPv4+IPv6) in BGP using"
        " network command for vrf RED_A on router R2"
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {
        "r2": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that static routes(IPv4+IPv6) is overridden and doesn't"
        " have duplicate entries within VRF RED_A on router RED-1"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        dut = "r3"
        input_dict_1 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK1_1[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Api call to modfiy BGP timers")

    input_dict_4 = {
        "r3": {
            "bgp": [
                {
                    "local_as": "200",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r3-link1": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r3-link1": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r3", vrf=["RED_A"])

    step("Repeat for 5 times.")

    for count in range(1, 2):
        step("Iteration {}..".format(count))
        step("Delete a specific VRF instance(RED_A) from router R3")

        input_dict = {"r3": {"vrfs": [{"name": "RED_A", "id": "1", "delete": True}]}}

        result = create_vrf_cfg(tgen, input_dict)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        step("Sleeping for {}+1 sec..".format(HOLDDOWNTIMER))
        sleep(HOLDDOWNTIMER + 1)

        for addr_type in ADDR_TYPES:
            dut = "r3"
            input_dict_1 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": NETWORK1_1[addr_type],
                            "next_hop": NEXT_HOP_IP[addr_type],
                            "vrf": "RED_A",
                        }
                    ]
                }
            }

            result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1, expected=False)
            assert (
                result is not True
            ), "Testcase {} : Failed \n Expected Behaviour: Routes are cleaned \n Error {}".format(tc_name, result)

        step("Add/reconfigure the same VRF instance again")

        result = create_vrf_cfg(tgen, {"r3": topo["routers"]["r3"]})
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        step(
            "After deleting VRFs ipv6 addresses will be deleted from kernel "
            " Adding back ipv6 addresses"
        )

        dut = "r3"
        vrf = "RED_A"

        for c_link, c_data in topo["routers"][dut]["links"].items():
            if c_data["vrf"] != vrf:
                continue

            intf_name = c_data["interface"]
            intf_ipv6 = c_data["ipv6"]

            create_interface_in_kernel(
                tgen, dut, intf_name, intf_ipv6, vrf, create=False
            )

        step("Sleeping for {}+1 sec..".format(HOLDDOWNTIMER))
        sleep(HOLDDOWNTIMER + 1)

        for addr_type in ADDR_TYPES:
            dut = "r3"
            input_dict_1 = {
                "r2": {
                    "static_routes": [
                        {
                            "network": NETWORK1_1[addr_type],
                            "next_hop": NEXT_HOP_IP[addr_type],
                            "vrf": "RED_A",
                        }
                    ]
                }
            }

            result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


def test_vrf_route_leaking_next_hop_interface_flapping_p1(request):
    """
    CHAOS_3:
    VRF leaking - next-hop interface is flapping.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Create loopback interface")

    for addr_type in ADDR_TYPES:
        create_interface_in_kernel(
            tgen,
            "red1",
            "loopback2",
            LOOPBACK_2[addr_type],
            "RED_B",
            LOOPBACK_2["{}_mask".format(addr_type)],
        )

    intf_red1_r11 = topo["routers"]["red1"]["links"]["r1-link2"]["interface"]
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": LOOPBACK_2[addr_type],
                        "interface": intf_red1_r11,
                        "nexthop_vrf": "RED_B",
                        "vrf": "RED_A",
                    }
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {
        "red1": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    step("VRF RED_A should install a route for vrf RED_B's " "loopback ip.")
    for addr_type in ADDR_TYPES:
        dut = "red1"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": LOOPBACK_2[addr_type],
                        "interface": intf_red1_r11,
                        "nexthop_vrf": "RED_B",
                        "vrf": "RED_A",
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1, protocol="static")
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step("Repeat step-2 to 4 at least 5 times")

    for count in range(1, 2):
        intf1 = topo["routers"]["red1"]["links"]["r1-link2"]["interface"]

        step(
            "Iteration {}: Shutdown interface {} on router"
            "RED_1.".format(count, intf1)
        )
        shutdown_bringup_interface(tgen, "red1", intf1, False)

        step("Verify that RED_A removes static route from routing " "table.")

        for addr_type in ADDR_TYPES:
            dut = "red1"
            input_dict_1 = {
                "red1": {
                    "static_routes": [
                        {
                            "network": LOOPBACK_2[addr_type],
                            "interface": intf_red1_r11,
                            "nexthop_vrf": "RED_B",
                            "vrf": "RED_A",
                        }
                    ]
                }
            }

            result = verify_rib(
                tgen, addr_type, dut, input_dict_1, protocol="static", expected=False
            )
            assert result is not True, (
                "Testcase {} : Failed \n Expected Behaviour: Routes are"
                " not present Error {}".format(tc_name, result)
            )

        step("Bring up interface {} on router RED_1 again.".format(intf1))
        shutdown_bringup_interface(tgen, "red1", intf1, True)

        step(
            "Verify that RED_A reinstalls static route pointing to "
            "RED_B's IP in routing table again"
        )

        for addr_type in ADDR_TYPES:
            dut = "red1"
            input_dict_1 = {
                "red1": {
                    "static_routes": [
                        {
                            "network": LOOPBACK_2[addr_type],
                            "interface": intf_red1_r11,
                            "nexthop_vrf": "RED_B",
                            "vrf": "RED_A",
                        }
                    ]
                }
            }

            result = verify_rib(tgen, addr_type, dut, input_dict_1, protocol="static")
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


def test_restart_bgpd_daemon_p1(request):
    """
    CHAOS_6:
    Restart BGPd daemon on DUT to check if all the
    routes in respective vrfs are reinstalled..
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    reset_config_on_routers(tgen)

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from RED_1"
        " in vrf instances(RED_A and RED_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Advertise unique BGP prefixes(IPv4+IPv6) from BLUE_1 in"
        " vrf instances(BLUE_A and BLUE_B)."
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Redistribute static..")

    input_dict_3 = {}
    for dut in ["red1", "blue1"]:
        temp = {dut: {"bgp": []}}
        input_dict_3.update(temp)

        if "red" in dut:
            VRFS = ["RED_A", "RED_B"]
            AS_NUM = [500, 500]
        elif "blue" in dut:
            VRFS = ["BLUE_A", "BLUE_B"]
            AS_NUM = [800, 800]

        for vrf, as_num in zip(VRFS, AS_NUM):
            temp[dut]["bgp"].append(
                {
                    "local_as": as_num,
                    "vrf": vrf,
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    },
                }
            )

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed\n Error {}".format(tc_name, result)

    step("Kill BGPd daemon on R1.")
    kill_router_daemons(tgen, "r1", ["bgpd"])

    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Routes are still present in VRF RED_A and RED_B \n Error: {}".format(
                tc_name, result
            )
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Routes are still present in VRF BLUE_A and BLUE_B \n Error: {}".format(
                tc_name, result
            )
        )

    step("Bring up BGPd daemon on R1.")
    start_router_daemons(tgen, "r1", ["bgpd"])

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    },
                ]
            }
        }

        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
