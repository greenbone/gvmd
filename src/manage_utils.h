/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: Manage library utilities.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef OPENVAS_MANAGER_MANAGE_UTILS_H
#define OPENVAS_MANAGER_MANAGE_UTILS_H

#include <time.h>

// Log message severity constant
#define SEVERITY_LOG 0.0
// False positive severity constant
#define SEVERITY_FP -1.0
// Debug message severity constant
#define SEVERITY_DEBUG -2.0
// Error message severity constant
#define SEVERITY_ERROR -3.0
// Constant for missing or invalid severity
#define SEVERITY_MISSING -99.0
// Constant for undefined severity (for ranges)
#define SEVERITY_UNDEFINED -98.0
// Maximum possible severity
#define SEVERITY_MAX 10.0
// Number of subdivisions for 1 severity point (10 => step size 0.1)
#define SEVERITY_SUBDIVISIONS 10

long
time_offset (const char *, time_t);

long
current_offset (const char *);

time_t add_months (time_t, int);

time_t months_between (time_t, time_t);

time_t
next_time (time_t, int, int, const char*, int);

int
manage_count_hosts_max (const char *, const char *, int);

double
level_min_severity (const char*, const char*);

double
level_max_severity (const char*, const char*);

int
valid_db_resource_type (const char*);

#endif /* not OPENVAS_MANAGER_MANAGE_UTILS_H */
