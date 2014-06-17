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
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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

time_t add_months (time_t, int);

time_t months_between (time_t, time_t);

time_t
next_time (time_t, int, int);

#endif /* not OPENVAS_MANAGER_MANAGE_UTILS_H */
