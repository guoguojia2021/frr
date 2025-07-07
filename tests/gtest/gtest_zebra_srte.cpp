/*
 * Label Manager tests.
 * Copyright (C) 2020 Volta Networks
 *                    Patrick Ruddy
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <gtest/gtest.h>
#include <iostream>
#include "test_zread_srv6_policy_set.h"
#include "test_zread_srv6_policy_delete.h"
#include "test_zread_rnh_register.h"
#include "test_zread_rnh_unregister.h"
#include "test_zread_route_add.h"
#include "test_zread_route_del.h"
#include "test_model.h"


int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
