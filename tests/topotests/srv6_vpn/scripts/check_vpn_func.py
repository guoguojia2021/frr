from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.lutil import luCommand
import time

luCommand(
        "ce1",
        'vtysh -c "conf ter" -c "router bgp 100" -c "address-family ipv4 unicast" -c "network 200.1.1.1/24 nonconnected"',
        ".",
        "none",
        "Add routes",
    )
time.sleep(20)
luCommand(
        "pe3",
        'vtysh -c "show bgp ipv4 vpn"',
        "200.1.1.0/24",
        "wait",
        "Check pe3 init vpn routes",
        30,
        False,
        0.5
    )
luCommand(
        "pe3",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "no import vpn"',
        ".",
        "none",
        "Delete import vpn",
    )
time.sleep(20)
luCommand(
        "ce3",
        'vtysh -c "show bgp ipv4"',
        "200.1.1.0/24",
        "fail",
        "Check ce3 routes after del import vpn",
    )
luCommand(
        "pe3",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "import vpn"',
        ".",
        "none",
        "Add import vpn",
    )
time.sleep(10)
luCommand(
        "ce3",
        'vtysh -c "show bgp ipv4"',
        "200.1.1.0/24",
        "wait",
        "Check ce3 routes after add import vpn",
        30,
        False,
        0.5
    )

luCommand(
        "pe1",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "no export vpn"',
        ".",
        "none",
        "Delete export vpn",
    )
time.sleep(20)
luCommand(
        "ce3",
        'vtysh -c "show bgp ipv4"',
        "200.1.1.0/24",
        "fail",
        "Check ce3 routes after del export vpn",
    )
luCommand(
        "pe1",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "export vpn"',
        ".",
        "none",
        "Add export vpn",
    )
time.sleep(10)
luCommand(
        "ce3",
        'vtysh -c "show bgp ipv4"',
        "200.1.1.0/24",
        "wait",
        "Check ce3 routes after add export vpn",
        30,
        False,
        0.5
    )


luCommand(
        "pe3",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "no rt vpn import 1:200"',
        ".",
        "none",
        "Delete import rt",
    )
time.sleep(20)
luCommand(
        "ce3",
        'vtysh -c "show bgp ipv4"',
        "200.1.1.0/24",
        "fail",
        "Check ce3 routes after del import rt",
    )
luCommand(
        "pe3",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "rt vpn import 1:200"',
        ".",
        "none",
        "Add import rt",
    )
time.sleep(10)
luCommand(
        "ce3",
        'vtysh -c "show bgp ipv4"',
        "200.1.1.0/24",
        "wait",
        "Check ce3 routes after add import rt",
        30,
        False,
        0.5
    )