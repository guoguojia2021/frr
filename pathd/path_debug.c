/*
 * Copyright (C) 2020  NetDEF, Inc.
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

#include <zebra.h>

#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <libyang/libyang.h>

#include "printfrr.h"
#include "ipaddr.h"

#include "pathd/path_debug.h"

THREAD_DATA char _debug_buff[DEBUG_BUFF_SIZE];

unsigned long pathd_debug_sbfd;
unsigned long pathd_debug_srv6;
unsigned long pathd_debug_db;
unsigned long pathd_debug_zebra;

/**
 * Gives the string representation of an srte_protocol_origin enum value.
 *
 * @param origin The enum value to convert to string
 * @return a constant string representation of the enum value
 */
const char *srte_protocol_origin_name(enum srte_protocol_origin origin)
{
	switch (origin) {
	case SRTE_ORIGIN_UNDEFINED:
		return "UNDEFINED";
	case SRTE_ORIGIN_PCEP:
		return "PCEP";
	case SRTE_ORIGIN_BGP:
		return "BGP";
	case SRTE_ORIGIN_LOCAL:
		return "LOCAL";
	default:
		return "UNKNOWN";
	}
}

/**
 * Gives the string representation of an srte_candidate_type enum value.
 *
 * @param origin The enum value to convert to string
 * @return a constant string representation of the enum value
 */
const char *srte_candidate_type_name(enum srte_candidate_type type)
{
	switch (type) {
	case SRTE_CANDIDATE_TYPE_EXPLICIT:
		return "EXPLICIT";
	case SRTE_CANDIDATE_TYPE_DYNAMIC:
		return "DYNAMIC";
	case SRTE_CANDIDATE_TYPE_UNDEFINED:
		return "UNDEFINED";
	default:
		return "UNKNOWN";
	}
}

/**
 * Gives the string representation of an objfun_type enum value.
 *
 * @param origin The enum value to convert to string
 * @return a constant string representation of the enum value
 */
const char *objfun_type_name(enum objfun_type type)
{
	switch (type) {
	case OBJFUN_UNDEFINED:
		return "UNDEFINED";
	case OBJFUN_MCP:
		return "MCP";
	case OBJFUN_MLP:
		return "MLP";
	case OBJFUN_MBP:
		return "MBP";
	case OBJFUN_MBC:
		return "MBC";
	case OBJFUN_MLL:
		return "MLL";
	case OBJFUN_MCC:
		return "MCC";
	case OBJFUN_SPT:
		return "SPT";
	case OBJFUN_MCT:
		return "MCT";
	case OBJFUN_MPLP:
		return "MPLP";
	case OBJFUN_MUP:
		return "MUP";
	case OBJFUN_MRUP:
		return "MRUP";
	case OBJFUN_MTD:
		return "MTD";
	case OBJFUN_MBN:
		return "MBN";
	case OBJFUN_MCTD:
		return "MCTD";
	case OBJFUN_MSL:
		return "MSL";
	case OBJFUN_MSS:
		return "MSS";
	case OBJFUN_MSN:
		return "MSN";
	default:
		return "UNKNOWN";
	}
}

DEFUN (debug_pathd_sbfd,
       debug_pathd_sbfd_cmd,
       "debug pathd sbfd",
       DEBUG_STR
       "Pathd configuration\n"
       "Debug option set for pathd sbfd\n")
{
	pathd_debug_sbfd = 1;
	return CMD_SUCCESS;
}

DEFUN (no_debug_pathd_sbfd,
       no_debug_pathd_sbfd_cmd,
       "no debug pathd sbfd",
       NO_STR
       DEBUG_STR
       "Pathd configuration\n"
       "Debug option set for pathd sbfd\n")
{
	pathd_debug_sbfd = 0;
	return CMD_SUCCESS;
}

DEFUN (debug_pathd_srv6,
       debug_pathd_srv6_cmd,
       "debug pathd srv6",
       DEBUG_STR
       "Pathd configuration\n"
       "Debug option set for pathd srv6\n")
{
	pathd_debug_srv6 = 1;
	return CMD_SUCCESS;
}

DEFUN (no_debug_pathd_srv6,
       no_debug_pathd_srv6_cmd,
       "no debug pathd srv6",
       NO_STR
       DEBUG_STR
       "Pathd configuration\n"
       "Debug option set for pathd srv6\n")
{
	pathd_debug_srv6 = 0;
	return CMD_SUCCESS;
}

DEFUN (debug_pathd_db,
       debug_pathd_db_cmd,
       "debug pathd db",
       DEBUG_STR
       "Pathd configuration\n"
       "Debug option set for pathd db\n")
{
	pathd_debug_db = 1;
	return CMD_SUCCESS;
}

DEFUN (no_debug_pathd_db,
       no_debug_pathd_db_cmd,
       "no debug pathd db",
       NO_STR
       DEBUG_STR
       "Pathd configuration\n"
       "Debug option set for pathd db\n")
{
	pathd_debug_db = 0;
	return CMD_SUCCESS;
}

DEFUN (debug_pathd_zebra,
       debug_pathd_zebra_cmd,
       "debug pathd zebra",
       DEBUG_STR
       "Pathd configuration\n"
       "Debug option set for pathd zebra\n")
{
	pathd_debug_zebra = 1;
	return CMD_SUCCESS;
}

DEFUN (no_debug_pathd_zebra,
       no_debug_pathd_zebra_cmd,
       "no debug pathd zebra",
       NO_STR
       DEBUG_STR
       "Pathd configuration\n"
       "Debug option set for pathd zebra\n")
{
	pathd_debug_zebra = 0;
	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_pathd,
	   show_debugging_pathd_cmd,
	   "show debugging [pathd]",
	   SHOW_STR
	   DEBUG_STR
	   "Pathd daemon\n")
{
	vty_out(vty, "PATHD debugging status:\n");
	if (pathd_debug_sbfd)
		vty_out(vty, "  Pathd sbfd debugging is on.\n");
	if (pathd_debug_srv6)
		vty_out(vty, "  Pathd srv6 debugging is on.\n");
	if (pathd_debug_db)
		vty_out(vty, "  Pathd db debugging is on.\n");
	if (pathd_debug_zebra)
		vty_out(vty, "  Pathd zebra debugging is on.\n");

	return CMD_SUCCESS;
}

/* Debug node. */
static int config_write_debug(struct vty *vty);
static struct cmd_node pathd_debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = config_write_debug,
};


static int config_write_debug(struct vty *vty)
{
	int write = 0;

	if (IS_PATHD_DEBUG_SBFD) {
		vty_out(vty, "debug pathd sbfd\n");
		write++;
	}
	if (IS_PATHD_DEBUG_SRV6) {
		vty_out(vty, "debug pathd srv6\n");
		write++;
	}
	if (IS_PATHD_DEBUG_DB) {
		vty_out(vty, "debug pathd db\n");
		write++;
	}
	if (IS_PATHD_DEBUG_ZEBRA) {
		vty_out(vty, "debug pathd zebra\n");
		write++;
	}

	return write;
}
void pathd_debug_init(void)
{
	pathd_debug_sbfd = 0;
	pathd_debug_srv6 = 0;
	pathd_debug_db = 0;
	pathd_debug_zebra = 0;

	install_node(&pathd_debug_node);

	install_element(ENABLE_NODE, &debug_pathd_sbfd_cmd);
	install_element(ENABLE_NODE, &no_debug_pathd_sbfd_cmd);
	install_element(ENABLE_NODE, &debug_pathd_srv6_cmd);
	install_element(ENABLE_NODE, &no_debug_pathd_srv6_cmd);
	install_element(ENABLE_NODE, &debug_pathd_db_cmd);
	install_element(ENABLE_NODE, &no_debug_pathd_db_cmd);
	install_element(ENABLE_NODE, &debug_pathd_zebra_cmd);
	install_element(ENABLE_NODE, &no_debug_pathd_zebra_cmd);
	install_element(ENABLE_NODE, &show_debugging_pathd_cmd);

	install_element(CONFIG_NODE, &debug_pathd_sbfd_cmd);
	install_element(CONFIG_NODE, &no_debug_pathd_sbfd_cmd);
	install_element(CONFIG_NODE, &debug_pathd_srv6_cmd);
	install_element(CONFIG_NODE, &no_debug_pathd_srv6_cmd);
	install_element(CONFIG_NODE, &debug_pathd_db_cmd);
	install_element(CONFIG_NODE, &no_debug_pathd_db_cmd);
	install_element(CONFIG_NODE, &debug_pathd_zebra_cmd);
	install_element(CONFIG_NODE, &no_debug_pathd_zebra_cmd);
}
