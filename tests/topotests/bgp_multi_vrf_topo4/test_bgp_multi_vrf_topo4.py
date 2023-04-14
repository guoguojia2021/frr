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

def test_delete_and_re_add_vrf_p1(request):
    """
    CHAOS_2:
    Delete a VRF instance from DUT and check if the routes get
    deleted from subsequent neighbour routers and appears again once VRF
    is re-added.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step(
        "Advertise unique prefixes in BGP using static redistribution"
        "for both vrfs (RED_A and RED_B) on router RED_1"
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
        "Advertise unique prefixes in BGP using static redistribution"
        " for both vrfs (BLUE_A and BLUE_B) on router BLUE_1."
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
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

    step("Redistribute static for vrfs RED_A and RED_B and BLUE_A and BLUE_B")

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

    step("Verifying RIB and FIB before deleting VRFs")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

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

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    },
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Api call to modfiy BGP timers")

    input_dict_4 = {
        "r1": {
            "bgp": [
                {
                    "local_as": "100",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link1": {
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
                                            "r1-link1": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link2": {
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
                                            "r1-link2": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link3": {
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
                                            "r1-link3": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "100",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r2": {
                                        "dest_link": {
                                            "r1-link4": {
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
                                            "r1-link4": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r1", vrf=["RED_A", "RED_B", "BLUE_A", "BLUE_B"])

    step("Delete vrfs RED_A and BLUE_A from R1.")

    input_dict = {
        "r1": {
            "vrfs": [
                {"name": "RED_A", "id": "1", "delete": True},
                {"name": "BLUE_A", "id": "3", "delete": True},
            ]
        }
    }

    result = create_vrf_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step(
        "R2 must not receive the prefixes(in respective vrfs)"
        "originated from RED_1 and BLUE_1."
    )

    step("Wait for {}+1 sec..".format(HOLDDOWNTIMER))
    sleep(HOLDDOWNTIMER + 1)

    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            },
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    }
                ]
            },
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert result is not True, (
            "Testcase {} :Failed \n Expected Behaviour:"
            " Routes are not present \n Error {}".format(tc_name, result)
        )

        result = verify_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert result is not True, (
            "Testcase {} :Failed \n Expected Behaviour:"
            " Routes are not present \n Error {}".format(tc_name, result)
        )

    step("Add vrfs again RED_A and BLUE_A on R1.")

    result = create_vrf_cfg(tgen, {"r1": topo["routers"]["r1"]})
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    create_interfaces_cfg(tgen, {"r1": topo["routers"]["r1"]})
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step(
        "After deleting VRFs ipv6 addresses will be deleted from kernel "
        " Adding back ipv6 addresses"
    )

    dut = "r1"
    vrfs = ["RED_A", "BLUE_A"]

    for vrf in vrfs:
        for c_link, c_data in topo["routers"][dut]["links"].items():
            if c_data["vrf"] != vrf:
                continue

            intf_name = c_data["interface"]
            intf_ipv6 = c_data["ipv6"]

            create_interface_in_kernel(
                tgen, dut, intf_name, intf_ipv6, vrf, create=False
            )

    step(
        "R2 should now receive the prefixes(in respective vrfs)"
        "again. Check the debugging logs as well. For verification"
        " use same commands as mention in step-3."
    )

    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            }
        }

        result = verify_bgp_convergence(tgen, topo)
        assert result is True, "Testcase {}: Failed\n Error {}".format(tc_name, result)

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    }
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_vrf_name_significance_p1(request):
    """
    CHAOS_4:
    Verify that VRF names are locally significant
    to a router, and end to end connectivity depends on unique
    virtual circuits (using VLANs or separate physical interfaces).
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

    step(
        "Advertise unique prefixes in BGP using static redistribution"
        "for both vrfs (RED_A and RED_B) on router RED_1"
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
        "Advertise unique prefixes in BGP using static redistribution"
        " for both vrfs (BLUE_A and BLUE_B) on router BLUE_1."
    )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
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

    step("Redistribute static for vrfs RED_A and RED_B and BLUE_A and BLUE_B")

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

    step("Configure allowas-in on red2 and blue2")

    input_dict_4 = {
        "red2": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "red2-link1": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "red2-link1": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "500",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "red2-link2": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "red2-link2": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
        "blue2": {
            "bgp": [
                {
                    "local_as": "800",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link1": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link1": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "800",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link2": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link2": {
                                                "allowas-in": {"number_occurences": 2}
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Verifying RIB and FIB before deleting VRFs")

    for addr_type in ADDR_TYPES:
        dut = "red2"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            }
        }
        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    }
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        dut = "blue2"
        input_dict_3 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    }
                ]
            }
        }

        input_dict_4 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    }
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_3)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_4)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_3)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_4)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

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
                                    "red2": {
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
                                    "red2": {
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
                },
                {
                    "local_as": "200",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "red2": {
                                        "dest_link": {
                                            "r3-link2": {
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
                                    "red2": {
                                        "dest_link": {
                                            "r3-link2": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "200",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "blue2": {
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
                                    "blue2": {
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
                },
                {
                    "local_as": "200",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "blue2": {
                                        "dest_link": {
                                            "r3-link2": {
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
                                    "blue2": {
                                        "dest_link": {
                                            "r3-link2": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
        "red2": {
            "bgp": [
                {
                    "local_as": "500",
                    "vrf": "RED_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "red2-link1": {
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
                                    "r3": {
                                        "dest_link": {
                                            "red2-link1": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "500",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "red2-link2": {
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
                                    "r3": {
                                        "dest_link": {
                                            "red2-link2": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
        "blue2": {
            "bgp": [
                {
                    "local_as": "800",
                    "vrf": "BLUE_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link1": {
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
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link1": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "800",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link2": {
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
                                    "r3": {
                                        "dest_link": {
                                            "blue2-link2": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        },
    }

    result = create_router_bgp(tgen, topo, input_dict_4)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r3", vrf=["RED_A", "RED_B", "BLUE_A", "BLUE_B"])

        clear_bgp(tgen, addr_type, "red2", vrf=["RED_A", "RED_B"])

        clear_bgp(tgen, addr_type, "blue2", vrf=["BLUE_A", "BLUE_B"])

    step("Delete vrfs RED_A and BLUE_A from R3")

    input_dict = {
        "r3": {
            "vrfs": [
                {"name": "RED_A", "id": "1", "delete": True},
                {"name": "BLUE_A", "id": "3", "delete": True},
            ]
        }
    }

    result = create_vrf_cfg(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Waiting for {}+1..".format(HOLDDOWNTIMER))
    sleep(HOLDDOWNTIMER + 1)

    step("Verify RIB and FIB after deleting VRFs")

    for addr_type in ADDR_TYPES:
        dut = "red2"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_1, expected=False)
        assert (
            result is not True
        ), "Testcase {} :Failed \n Expected Behaviour: Routes are not present \n Error {}".format(tc_name, result)

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1, expected=False)
        assert (
            result is not True
        ), "Testcase {} :Failed \n Expected Behaviour: Routes are not present \n Error {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        dut = "blue2"
        input_dict_2 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert result is not True, (
            "Testcase {} :Failed \n Expected Behaviour: Routes are not present \n Error {}".format(tc_name, result)
        )

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2, expected=False)
        assert result is not True, (
            "Testcase {} :Failed \n Expected Behaviour: Routes are not present \n Error {}".format(tc_name, result)
        )

    step("Create 2 new VRFs PINK_A and GREY_A IN R3")

    topo_modify = deepcopy(topo)
    topo_modify["routers"]["r3"]["vrfs"][0]["name"] = "PINK_A"
    topo_modify["routers"]["r3"]["vrfs"][0]["id"] = "1"
    topo_modify["routers"]["r3"]["vrfs"][2]["name"] = "GREY_A"
    topo_modify["routers"]["r3"]["vrfs"][2]["id"] = "3"

    topo_modify["routers"]["r3"]["links"]["red2-link1"]["vrf"] = "PINK_A"
    topo_modify["routers"]["r3"]["links"]["blue2-link1"]["vrf"] = "GREY_A"

    topo_modify["routers"]["r3"]["links"]["r2-link1"]["vrf"] = "PINK_A"
    topo_modify["routers"]["r3"]["links"]["r2-link3"]["vrf"] = "GREY_A"

    topo_modify["routers"]["r3"]["links"]["r4-link1"]["vrf"] = "PINK_A"
    topo_modify["routers"]["r3"]["links"]["r4-link3"]["vrf"] = "GREY_A"

    topo_modify["routers"]["r3"]["bgp"][0]["vrf"] = "PINK_A"
    topo_modify["routers"]["r3"]["bgp"][2]["vrf"] = "GREY_A"

    result = create_vrf_cfg(tgen, {"r3": topo_modify["routers"]["r3"]})
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    create_interfaces_cfg(tgen, {"r3": topo_modify["routers"]["r3"]})
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = create_router_bgp(tgen, topo_modify["routers"])
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Api call to modfiy BGP timers")

    input_dict_4 = {
        "r3": {
            "bgp": [
                {
                    "local_as": "200",
                    "vrf": "PINK_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "red2": {
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
                                    "red2": {
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
                },
                {
                    "local_as": "200",
                    "vrf": "RED_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "red2": {
                                        "dest_link": {
                                            "r3-link2": {
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
                                    "red2": {
                                        "dest_link": {
                                            "r3-link2": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
                {
                    "local_as": "200",
                    "vrf": "GREY_A",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "blue2": {
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
                                    "blue2": {
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
                },
                {
                    "local_as": "200",
                    "vrf": "BLUE_B",
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "neighbor": {
                                    "blue2": {
                                        "dest_link": {
                                            "r3-link2": {
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
                                    "blue2": {
                                        "dest_link": {
                                            "r3-link2": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    },
                },
            ]
        }
    }

    result = create_router_bgp(tgen, topo_modify, input_dict_4)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r3", vrf=["PINK_A", "RED_B", "GREY_A", "BLUE_B"])

    step(
        "After deleting VRFs ipv6 addresses will be deleted from kernel "
        " Adding back ipv6 addresses"
    )

    dut = "r3"
    vrfs = ["GREY_A", "PINK_A"]

    for vrf in vrfs:
        for c_link, c_data in topo_modify["routers"][dut]["links"].items():
            if c_data["vrf"] != vrf:
                continue

            intf_name = c_data["interface"]
            intf_ipv6 = c_data["ipv6"]

            create_interface_in_kernel(
                tgen, dut, intf_name, intf_ipv6, vrf, create=False
            )

    step("Waiting for {}+1 sec..".format(HOLDDOWNTIMER))
    sleep(HOLDDOWNTIMER + 1)

    step(
        "Advertised prefixes should appear again in respective VRF"
        " table on routers RED_2 and BLUE_2. Verify fib and rib entries"
    )

    for addr_type in ADDR_TYPES:
        dut = "red2"
        input_dict_1 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_A",
                    }
                ]
            }
        }

        input_dict_2 = {
            "red1": {
                "static_routes": [
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED_B",
                    }
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_2)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        dut = "blue2"
        input_dict_3 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_A",
                    }
                ]
            }
        }

        input_dict_4 = {
            "blue1": {
                "static_routes": [
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "BLUE_B",
                    }
                ]
            }
        }

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_3)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_4)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_3)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        result = verify_rib(tgen, addr_type, dut, input_dict_4)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_restart_frr_services_p1(request):
    """
    CHAOS_8:
    Restart all FRR services (reboot DUT) to check if all
    the routes in respective vrfs are reinstalled.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    reset_config_on_routers(tgen)

    if tgen.routers_have_failure():
        check_router_status(tgen)

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

    step("Restart frr on R1")
    stop_router(tgen, "r1")
    start_router(tgen, "r1")

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
