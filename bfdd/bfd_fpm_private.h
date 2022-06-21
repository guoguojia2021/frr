/*
 * Private header file for the zebra FPM module.
 *
 * Copyright (C) 2012 by Open Source Routing.
 * Copyright (C) 2012 by Internet Systems Consortium, Inc. ("ISC")
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_FPM_PRIVATE_H
#define _ZEBRA_FPM_PRIVATE_H

#include "zebra/debug.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L

#define bfpm_debug(...)                                                        \
	do {                                                                   \
		zlog_debug("FPM: " __VA_ARGS__);                       \
	} while (0)

#elif defined __GNUC__

#define bfpm_debug(_args...)                                                   \
	do {                                                                   \
		zlog_debug("FPM: " _args);                             \
	} while (0)

#else
static inline void bfpm_debug(const char *format, ...)
{
	return;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_FPM_PRIVATE_H */
