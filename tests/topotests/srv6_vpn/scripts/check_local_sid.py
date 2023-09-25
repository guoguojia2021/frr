from lib.lutil import luCommand
import time

luCommand(
    "pe1",
    'vtysh -c "show ipv6 route"',
    "fd00:301:2021:fff1:eee::/80",
    "pass",
    "Op: check static route on pe1",
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "segment-routing" -c "srv6" -c "locators" -c "locator a prefix fd00:301:2021::/80 block-len 32 node-len 16 func-bits 32 argu-bits 48" -c "no opcode ::FFF1:0EEE:0:0:0"',
    ".",
    "fail",
    "Op: no opcode",
)
luCommand(
    "pe1",
    'vtysh -c "show ipv6 route"',
    "fd00:301:2021:fff1:eee::/80",
    "fail",
    "Check: no opcode",
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "segment-routing" -c "srv6" -c "locators" -c "locator a prefix fd00:301:2021::/80 block-len 32 node-len 16 func-bits 32 argu-bits 48" -c "opcode ::FFF1:0EEE:0:0:0 end-dt46 vrf PUBLIC-TC0"',
    ".",
    "fail",
    "Op: re-install opcode",
)
luCommand(
    "pe1",
    'vtysh -c "show ipv6 route"',
    "fd00:301:2021:fff1:eee::/80",
    "pass",
    "Op: check install route on pe1",
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "segment-routing" -c "srv6" -c "locators" -c "no locator a"',
    ".",
    "fail",
    "Op: re-install opcode",
)
luCommand(
    "pe1",
    'vtysh -c "show ipv6 route"',
    "fd00:301:2021:fff1:eee::/80",
    "fail",
    "Check: no locator",
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "segment-routing" -c "srv6" -c "locators" -c "locator a prefix fd00:301:2021::/80 block-len 32 node-len 16 func-bits 32 argu-bits 48" -c "opcode ::FFF1:0EEE:0:0:0 end-dt46 vrf PUBLIC-TC0"',
    ".",
    "fail",
    "Op: re-install locator",
)
luCommand(
    "pe1",
    'vtysh -c "show ipv6 route"',
    "fd00:301:2021:fff1:eee::/80",
    "pass",
    "Check: no opcode",
)

