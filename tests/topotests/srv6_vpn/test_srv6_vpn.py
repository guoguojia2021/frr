#!/usr/bin/env python

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2018, LabN Consulting, L.L.C.
# Authored by Lou Berger <lberger@labn.net>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

import os
import sys
import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../"))

from lib.ltemplate import *

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.esr]


def SKIP_test_check_vpn_sid():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = None
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/check_vpn_sid.py", False, CliOnFail, CheckFunc)

def test_check_local_sid():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = None
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/check_local_sid.py", False, CliOnFail, CheckFunc)

def test_check_import_sid():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = None
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/check_import_sid.py", False, CliOnFail, CheckFunc)

def test_check_color():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = None
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/check_color.py", False, CliOnFail, CheckFunc)

def test_check_vpn_func():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = None
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/check_vpn_func.py", False, CliOnFail, CheckFunc)

def test_check_policy_sid():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = None
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/check_policy_config.py", False, CliOnFail, CheckFunc)

def test_check_policy_func():
    CliOnFail = None
    # For debugging, uncomment the next line
    # CliOnFail = 'tgen.mininet_cli'
    CheckFunc = None
    # uncomment next line to start cli *before* script is run
    # CheckFunc = 'ltemplateVersionCheck(\'4.1\', cli=True, iproute2=\'4.9\')'
    ltemplateTest("scripts/check_policy_func.py", False, CliOnFail, CheckFunc)

if __name__ == "__main__":
    retval = pytest.main(["-s"])
    sys.exit(retval)
