from lib.lutil import luCommand
from lib.topogen import Topogen, TopoRouter, get_topogen
import time
import pdb

luCommand(
    "pe1",
    'vtysh -c "show run"',
    "segment-list",
    "pass",
    "see segment-list in running-config"
)
luCommand(
    "pe1",
    'vtysh -c "show run"',
    "index",
    "pass",
    "see index in running-config"
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "segment-routing" -c "traffic-eng" -c "segment-list b" -c "index 1 ipv6-address 200::178"',
    ".",
    "fail",
    "Test of segment-list, index and f-i-l-s"
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "segment-routing" -c "traffic-eng" -c "policy color 1 endpoint 1000::179" -c \
    "candidate-path preference 1 name a explicit segment-list a weight 1" -c \
    "candidate-path preference 2 name b explicit segment-list b weight 2"',
    ".",
    "fail",
    "Adding two candidate-path"
)
luCommand(
    "pe1",
    'vtysh -c "show sr-te policy detail"',
    "CandidateName: a.*CandidateName: b",
    "pass",
    "see candidate-path a and b"
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "segment-routing" -c "traffic-eng" -c "policy color 1 endpoint 1000::179" -c \
    "no candidate-path preference 2 name b explicit segment-list b"',
    ".",
    "fail",
    "delete candidate-path b"
)
luCommand(
    "pe1",
    'vtysh -c "show sr-te policy detail"',
    "CandidateName: b",
    "fail",
    "shouldn't see candidate-path b"
)
luCommand(
    "pe1",
    'vtysh -c "conf t" -c "segment-routing" -c "traffic-eng" -c "policy color 1 endpoint 1000::179" -c \
    "candidate-path preference 1 name a explicit segment-list a weight 99"',
    ".",
    "fail",
    "change weight of candidate-path a"
)
luCommand(
    "pe1",
    'vtysh -c "show sr-te policy detail"',
    "Status: UP",
    "pass",
    "change weight successfully"
)


