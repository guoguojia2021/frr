from lib.lutil import luCommand
from lib.topogen import Topogen, TopoRouter, get_topogen
import time
import pdb

num = 1000
b = int(num / (256 * 256))
if b > 0:
    r = num - b * (256 * 256)
else:
    r = num
c = int(r / 256)
if c > 0:
    d = r - c * 256 - 1
else:
    d = r

luCommand("pe1", 'vtysh -c "show ip  bgp  vrf PUBLIC-TC0 ipv4 neighbors 192.168.1.2"', "Established", "wait", "neighbors establish", 30)

luCommand(
    "ce1",
    'vtysh -c "sharp install routes 10.0.0.0 nexthop 99.0.0.1 {}"'.format(num),
    ".",
    "fail",
    "Adding {} routes".format(num),
)
time.sleep(10)
luCommand(
    "pe1",
    'vtysh -c "show bgp ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
    "fd00:301:2021:fff1:eee::",
    "pass",
    "should see VPN sid",
)
luCommand("pe1", 'vtysh -c "show bgp neighbors fd00:0:200:101::"', "Established", "wait", "neighbors establish", 30)
time.sleep(30)
luCommand(
    "pe3",
    'vtysh -c "show bgp ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
    "fd00:301:2021:fff1:eee::",
    "pass",
    "should see VPN sid",
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "router bgp 200 vrf PUBLIC-TC0" -c "no srv6-locator a"',
    ".",
    "fail",
    "Deletion of srv6-locator"
)
time.sleep(10)
luCommand(
    "pe3",
    'vtysh -c "show bgp ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
    "fd00:301:2021:fff1:eee::",
    "fail",
    "shouldn't see VPN sid",
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "router bgp 200 vrf PUBLIC-TC0" -c "srv6-locator a"',
    ".",
    "fail",
    "Re-installation of srv6-locator"
)
time.sleep(10)
luCommand(
    "pe3",
    'vtysh -c "show bgp ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
    "fd00:301:2021:fff1:eee::",
    "pass",
    "should see VPN sid",
)
luCommand(
    "ce1",
    'vtysh -c "sharp remove routes 10.0.0.0 {}"'.format(num),
    ".",
    "fail",
    "Removing {} routes".format(num),
)
time.sleep(10)
luCommand(
    "pe3",
    'vtysh -c "show bgp ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
    '1:10.{}.{}.{}'.format(b, c, d),
    "fail",
    "Successfully remove routes",
)
luCommand(
    "ce1",
    'vtysh -c "sharp install routes 10.0.0.0 nexthop 99.0.0.1 {}"'.format(num),
    ".",
    "fail",
    "Adding {} routes".format(num),
)
time.sleep(10)
luCommand(
    "pe3",
    'vtysh -c "show bgp ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
    "fd00:301:2021:fff1:eee::",
    "pass",
    "should see VPN sid",
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "segment-routing" -c "srv6" -c "locators" -c "locator a prefix fd00:301:2021::/48 block-len 32 node-len 16 func-bits 32 argu-bits 48" -c "no opcode ::FFF1:0EEE:0:0:0"',
    ".",
    "fail",
    "Deletion of opcode",
)
time.sleep(10)
luCommand(
    "pe3",
    'vtysh -c "show bgp ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
    "fd00:301:2021:fff1:eee::",
    "fail",
    "shouldn't see VPN sid",
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "segment-routing" -c "srv6" -c "locators" -c "locator a prefix fd00:301:2021::/48 block-len 32 node-len 16 func-bits 32 argu-bits 48" -c \
    "opcode ::FFF1:0222:0:0:0 end-dt46 vrf PUBLIC-TC0"',
    ".",
    "fail",
    "Dynamic installation of new opcode",
)
time.sleep(10)
luCommand(
    "pe3",
    'vtysh -c "show bgp ipv4 vpn 10.{}.{}.{}"'.format(b, c, d),
    "fd00:301:2021:fff1:222::",
    "pass",
    "should see new VPN sid",
)
