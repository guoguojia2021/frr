from lib.lutil import luCommand
import time

# set the route-map color on pe1
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "route-map sr2 permit 10" -c "set extcommunity color 2"',
    ".",
    "fail",
    "Op: set the route-map color on pe1",
)
time.sleep(10)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "route bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "route-map vpn export sr2" -c "export vpn" -c "network 200.0.0.0/24 nonconnected" -c "network 200.0.0.1/32 nonconnected"',
    ".",
    "fail",
    "Op: set the export color and network two routes on pe1",
)
time.sleep(10)
luCommand(
    "pe1",
    'vtysh -c "show bgp ipv4 vpn 200.0.0.0/24"',
    "Color:01:2",
    "pass",
    "Check: color on pe1",
)
time.sleep(10)

# add/delete the export vpn and check if the result is right
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "route bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "no export vpn"',
    ".",
    "fail",
    "Op: Delete the export vpn on pe1",
)
time.sleep(10)
luCommand(
    "pe1",
    'vtysh -c "show bgp ipv4 vpn"',
    "No",
    "pass",
    "Check: Delete the export vpn on pe1",
)
time.sleep(10)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "route bgp 200 vrf PUBLIC-TC0" -c "address-family ipv4 unicast" -c "export vpn"',
    ".",
    "fail",
    "Op: Re-install export vpn",
)
time.sleep(10)
luCommand(
    "pe1",
    'vtysh -c "show bgp ipv4 vpn 200.0.0.0/24"',
    "Color:01:2",
    "pass",
    "Check: add/re-install export vpn",
)
time.sleep(10)

# config the route-map first then the export vpn and check the result: Done before

# change the color and check the result
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "route-map sr2 permit 10" -c "set extcommunity color 10"',
    ".",
    "fail",
    "Op: Change the color",
)
time.sleep(10)
luCommand(
    "pe1",
    'vtysh -c "show bgp ipv4 vpn 200.0.0.0/24"',
    "Color:01:10",
    "pass",
    "Check: the change of color",
)
time.sleep(10)

# delete the color and check the routes
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "route-map sr2 permit 10" -c "no set extcommunity color 10"',
    ".",
    "fail",
    "Op: Delete the color",
)
time.sleep(10)
luCommand(
    "pe1",
    'vtysh -c "show bgp ipv4 vpn 200.0.0.0/24"',
    "Color",
    "fail",
    "Check: Delete the color",
)
time.sleep(10)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "route-map sr2 permit 10" -c "set extcommunity color 2"',
    ".",
    "fail",
    "Op: re-install the pe1 sr2 color 2",
)
time.sleep(10)

# check the remote dev and if the policy iteration is right
# set the policy configuration on pe3
luCommand(
    "pe3",
    'vtysh -c "conf t" -c "segment-routing" -c "traffic-eng" -c "segment-list a" -c "index 1 ipv6-address abcd:100:181:251::2"',
    ".",
    "fail",
    "Op: set segment-list on pe3"
)
luCommand(
    "pe3",
    'vtysh -c "conf t" -c "segment-routing" -c "traffic-eng" -c "policy color 2 endpoint fd00:0:200:171::" -c "candidate-path preference 1 name a explicit segment-list a weight 1"',
    ".",
    "fail",
    "Op: set policy on pe3",
)
time.sleep(10)
# install route from ce1
luCommand(
    "ce1",
    'vtysh -c "sharp install routes 33.0.0.0 nexthop 192.168.1.2 2"',
    ".",
    "fail",
    "Op: install route from ce1",
)
time.sleep(10)
# check results on pe3
luCommand(
    "pe3",
    'vtysh -c "show bgp ipv4 vpn 33.0.0.0/32"',
    "fd00:0:200:171::|2",
    "pass",
    "Check: policy iteration on remote dev pe3",
)
