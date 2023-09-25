from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.lutil import luCommand
import time
import pdb

luCommand(
        "ce1",
        'vtysh -c "conf ter" -c "router bgp 100" -c "address-family ipv4 unicast" -c "network 200.1.0.1/32 nonconnected"',
        ".",
        "none",
        "Add routes",
    )

luCommand(
        "pe3",
        'vtysh -c "conf ter" -c "segment-routing" -c "traffic-eng" -c "segment-list a" -c "index 1 ipv6-address fd00:0:200:181::"',
        ".",
        "none",
        "Add segment-list",
)
luCommand(
        "pe3",
        'vtysh -c "conf ter" -c "segment-routing" -c "traffic-eng" -c "policy color 1 endpoint fd00:0:200:171::" -c "candidate-path preference 1 name a explicit segment-list a weight 1"',
        ".",
        "none",
        "Add policy & cpath",
)
luCommand(
        "pe1",
        'vtysh -c "conf ter" -c "route-map sr1 permit 10" -c "set extcommunity color 1"',
        ".",
        "none",
        "Add color",
)
luCommand(
        "pe1",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "route-map vpn export sr1"',
        ".",
        "none",
        "Add route-map",
)

time.sleep(5)
luCommand(
        "pe3",
        'vtysh -c "show ip route vrf PUBLIC-TC0 200.1.0.1"',
        "srv6tunnel\(endpoint\|color\):fd00:0:200:171::\|1",
        "pass",
        "Init check",
)
luCommand(
        "pe3",
        'vtysh -c "conf ter" -c "segment-routing" -c "traffic-eng" -c "policy color 1 endpoint fd00:0:200:171::" -c "no candidate-path preference 1 name a explicit segment-list a"',
        ".",
        "none",
        "Delete cpath",
)
time.sleep(5)
luCommand(
        "pe3",
        'vtysh -c "show ip route vrf PUBLIC-TC0 200.1.0.1"',
        "srv6tunnel\(endpoint\|color\):fd00:0:200:171::\|1",
        "fail",
        "Check after del cpath",
)
luCommand(
        "pe3",
        'vtysh -c "conf ter" -c "segment-routing" -c "traffic-eng" -c "policy color 1 endpoint fd00:0:200:171::" -c "candidate-path preference 1 name a explicit segment-list a weight 1"',
        ".",
        "none",
        "Add cpath",
)
time.sleep(5)
luCommand(
        "pe3",
        'vtysh -c "show ip route vrf PUBLIC-TC0 200.1.0.1"',
        "srv6tunnel\(endpoint\|color\):fd00:0:200:171::\|1",
        "pass",
        "Check after add cpath",
)
luCommand(
        "pe3",
        'vtysh -c "conf ter" -c "segment-routing" -c "traffic-eng" -c "no policy color 1 endpoint fd00:0:200:171::"',
        ".",
        "none",
        "Delete policy",
)
time.sleep(5)
luCommand(
        "pe3",
        'vtysh -c "show ip route vrf PUBLIC-TC0 200.1.0.1"',
        "srv6tunnel\(endpoint\|color\):fd00:0:200:171::\|1",
        "fail",
        "Check after del policy",
)
luCommand(
        "pe3",
        'vtysh -c "conf ter" -c "segment-routing" -c "traffic-eng" -c "policy color 1 endpoint fd00:0:200:171::" -c "candidate-path preference 1 name a explicit segment-list a weight 1"',
        ".",
        "none",
        "Add policy & cpath",
)
time.sleep(5)
luCommand(
        "pe3",
        'vtysh -c "show ip route vrf PUBLIC-TC0 200.1.0.1"',
        "srv6tunnel\(endpoint\|color\):fd00:0:200:171::\|1",
        "pass",
        "Check after add policy",
)
luCommand(
        "pe1",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "no route-map vpn export sr1"',
        ".",
        "none",
        "Delete route-map",
)
time.sleep(5)
luCommand(
        "pe3",
        'vtysh -c "show ip route vrf PUBLIC-TC0 200.1.0.1"',
        "srv6tunnel\(endpoint\|color\):fd00:0:200:171::\|1",
        "fail",
        "Check after del route-map",
)
luCommand(
        "pe1",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "route-map vpn export sr1"',
        ".",
        "none",
        "Add route-map",
)
time.sleep(5)
luCommand(
        "pe3",
        'vtysh -c "show ip route vrf PUBLIC-TC0 200.1.0.1"',
        "srv6tunnel\(endpoint\|color\):fd00:0:200:171::\|1",
        "pass",
        "Check after add route-map",
)
luCommand(
        "pe1",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "no srv6-locator a"',
        ".",
        "none",
        "Delete sid",
)
time.sleep(5)
luCommand(
        "pe3",
        'vtysh -c "show ip route vrf PUBLIC-TC0 200.1.0.1"',
        "srv6tunnel\(endpoint\|color\):fd00:0:200:171::\|1",
        "fail",
        "Check after del sid",
)
luCommand(
        "pe1",
        'vtysh -c "conf ter" -c "router bgp 200 vrf PUBLIC-TC0" -c "srv6-locator a"',
        ".",
        "none",
        "Add sid",
)
time.sleep(5)
luCommand(
        "pe3",
        'vtysh -c "show ip route vrf PUBLIC-TC0 200.1.0.1"',
        "srv6tunnel\(endpoint\|color\):fd00:0:200:171::\|1",
        "pass",
        "Check after add sidß",
)