from lib.lutil import luCommand
from time import sleep
from lib.bgprib import bgpribRequireUnicastRoutes

luCommand(
    "r2",
    'vtysh -c "conf ter" -c "bgp advertise-delay 10"',
    ".",
    "none",
    "Config ip nht route-map",
)

ipv4_want = [
    {"p": "1.1.1.1/32", "n": "10.0.1.1"},
    {"p": "1.1.1.1/32", "n": "10.0.2.1"},
]
bgpribRequireUnicastRoutes("r2", "ipv4", "", "", ipv4_want)

ipv6_want = [
    {"p": "1::1/128", "n": "10:10::10"},
    {"p": "1::1/128", "n": "10:20::10"},
    {"p": "1000::1000/128", "n": "10:10::10"},
    {"p": "1000::1000/128", "n": "10:20::10"},
]
bgpribRequireUnicastRoutes("r2", "ipv6", "", "", ipv6_want)

luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11" -c "neighbor 10.0.2.2 shutdown" -c "neighbor 10:20::20 shutdown"',
    ".",
    "none",
    "Shutdown bgp peer",
)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11" -c "no neighbor 10.0.2.2 shutdown" -c "no neighbor 10:20::20 shutdown"',
    ".",
    "none",
    "Shutdown bgp peer",
)
sleep(2)
ipv4_want = [
    {"p": "1.1.1.1/32", "n": "10.0.1.1"},
]
bgpribRequireUnicastRoutes("r2", "ipv4", "", "", ipv4_want)

ipv6_want = [
    {"p": "1::1/128", "n": "10:10::10"},
    {"p": "1000::1000/128", "n": "10:10::10"},
]
bgpribRequireUnicastRoutes("r2", "ipv6", "", "", ipv6_want)

sleep(12)

ipv4_want = [
    {"p": "1.1.1.1/32", "n": "10.0.1.1"},
    {"p": "1.1.1.1/32", "n": "10.0.2.1"},
]
bgpribRequireUnicastRoutes("r2", "ipv4", "", "", ipv4_want)

ipv6_want = [
    {"p": "1::1/128", "n": "10:10::10"},
    {"p": "1::1/128", "n": "10:20::10"},
    {"p": "1000::1000/128", "n": "10:10::10"},
    {"p": "1000::1000/128", "n": "10:20::10"},
]
bgpribRequireUnicastRoutes("r2", "ipv6", "", "", ipv6_want)

luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11" -c "address-family ipv4 unicast" -c "neighbor 10.0.2.2 advertise-delay-map ip-advertise-map"',
    ".",
    "none",
    "Config advertise delay route-map",
)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11" -c "address-family ipv6 unicast" -c "neighbor 10:20::20 advertise-delay-map ipv6-advertise-map"',
    ".",
    "none",
    "Config advertise delay route-map",
)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11" -c "neighbor 10.0.2.2 shutdown" -c "neighbor 10:20::20 shutdown"',
    ".",
    "none",
    "Shutdown bgp peer",
)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11" -c "no neighbor 10.0.2.2 shutdown" -c "no neighbor 10:20::20 shutdown"',
    ".",
    "none",
    "Shutdown bgp peer",
)
sleep(2)
ipv4_want = [
    {"p": "1.1.1.1/32", "n": "10.0.1.1"},
    {"p": "1.1.1.1/32", "n": "10.0.2.1"},
]
bgpribRequireUnicastRoutes("r2", "ipv4", "", "", ipv4_want)

ipv6_want = [
    {"p": "1::1/128", "n": "10:10::10"},
    {"p": "1::1/128", "n": "10:20::10"},
]
bgpribRequireUnicastRoutes("r2", "ipv6", "", "", ipv6_want)
sleep(12)

ipv4_want = [
    {"p": "1.1.1.1/32", "n": "10.0.1.1"},
    {"p": "1.1.1.1/32", "n": "10.0.2.1"},
]
bgpribRequireUnicastRoutes("r2", "ipv4", "", "", ipv4_want)

ipv6_want = [
    {"p": "1::1/128", "n": "10:10::10"},
    {"p": "1::1/128", "n": "10:20::10"},
    {"p": "1000::1000/128", "n": "10:10::10"},
    {"p": "1000::1000/128", "n": "10:20::10"},
]
bgpribRequireUnicastRoutes("r2", "ipv6", "", "", ipv6_want)

luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11" -c "address-family ipv4 unicast" -c "no neighbor 10.0.2.2 advertise-delay-map ip-advertise-map"',
    ".",
    "none",
    "Config advertise delay route-map",
)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11" -c "address-family ipv6 unicast" -c "no neighbor 10:20::20 advertise-delay-map ipv6-advertise-map"',
    ".",
    "none",
    "Config advertise delay route-map",
)
luCommand(
    "r2",
    'vtysh -c "conf ter" -c "no bgp advertise-delay 10"',
    ".",
    "none",
    "Config advertise-delay",
)

luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11" -c "neighbor 10.0.2.2 shutdown" -c "neighbor 10:20::20 shutdown"',
    ".",
    "none",
    "Shutdown bgp peer",
)
luCommand(
    "r1",
    'vtysh -c "conf ter" -c "router bgp 11" -c "no neighbor 10.0.2.2 shutdown" -c "no neighbor 10:20::20 shutdown"',
    ".",
    "none",
    "Shutdown bgp peer",
)
sleep(5)
ipv4_want = [
    {"p": "1.1.1.1/32", "n": "10.0.1.1"},
    {"p": "1.1.1.1/32", "n": "10.0.2.1"},
]
bgpribRequireUnicastRoutes("r2", "ipv4", "", "", ipv4_want)

ipv6_want = [
    {"p": "1::1/128", "n": "10:10::10"},
    {"p": "1::1/128", "n": "10:20::10"},
    {"p": "1000::1000/128", "n": "10:10::10"},
    {"p": "1000::1000/128", "n": "10:20::10"},
]
bgpribRequireUnicastRoutes("r2", "ipv6", "", "", ipv6_want)