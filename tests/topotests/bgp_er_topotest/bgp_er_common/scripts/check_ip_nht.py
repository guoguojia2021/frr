from lib.lutil import luCommand
from time import sleep
from lib.bgprib import bgpribRequireUnicastRoutes

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
    "r2",
    'vtysh -c "conf ter" -c "ip nht bgp route-map ip-nht-map" -c "ipv6 nht bgp route-map ipv6-nht-map"',
    ".",
    "none",
    "Config ip nht route-map",
)
luCommand(
    "r2",
    'vtysh -c "show ip route 1.1.1.1 json"',
    "\"internalNextHopActiveNum\":1,",
    "pass",
    "Redundant route 1 details",
)

luCommand(
    "r2",
    'vtysh -c "show ipv6 route 1::1/128 json"',
    "\"internalNextHopActiveNum\":1,",
    "pass",
    "Redundant route 1 details",
)


luCommand(
    "r2",
    'vtysh -c "conf ter" -c "ip prefix-list ip_nht seq 15 permit 10.0.2.1/24 le 32" -c "ipv6 prefix-list ipv6_nht seq 15 permit 10:20::20/64 le 128"',
    ".",
    "none",
    "Update ip nht route-map",
)
sleep(8)
luCommand(
    "r2",
    'vtysh -c "show ip route 1.1.1.1 json"',
    "\"internalNextHopActiveNum\":2,",
    "pass",
    "Redundant route 1 details",
)

luCommand(
    "r2",
    'vtysh -c "show ipv6 route 1::1/128 json"',
    "\"internalNextHopActiveNum\":2,",
    "pass",
    "Redundant route 1 details",
)

luCommand(
    "r2",
    'vtysh -c "conf ter" -c "no ip prefix-list ip_nht seq 15 permit 10.0.2.1/24 le 32" -c "no ipv6 prefix-list ipv6_nht seq 15 permit 10:20::20/64 le 128"',
    ".",
    "none",
    "Update ip nht route-map",
)
sleep(8)
luCommand(
    "r2",
    'vtysh -c "show ip route 1.1.1.1 json"',
    "\"internalNextHopActiveNum\":1,",
    "pass",
    "Redundant route 1 details",
)

luCommand(
    "r2",
    'vtysh -c "show ipv6 route 1::1/128 json"',
    "\"internalNextHopActiveNum\":1",
    "pass",
    "Redundant route 1 details",
)
luCommand(
    "r2",
    'vtysh -c "conf ter" -c "no ip nht bgp route-map ip-nht-map" -c "no ipv6 nht bgp route-map ipv6-nht-map"',
    ".",
    "none",
    "Config no ip nht route-map",
)
luCommand(
    "r2",
    'vtysh -c "show ip route 1.1.1.1 json"',
    "\"internalNextHopActiveNum\":2,",
    "pass",
    "Redundant route 1 details",
)

luCommand(
    "r2",
    'vtysh -c "show ipv6 route 1::1/128 json"',
    "\"internalNextHopActiveNum\":2,",
    "pass",
    "Redundant route 1 details",
)