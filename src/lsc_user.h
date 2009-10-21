/* OpenVAS Manager
 * $Id$
 * Description: LSC user credentials package generation.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@intevation.de>
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
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

#ifndef _OPENVASMD_LSC_USER_H
#define _OPENVASMD_LSC_USER_H

#include <glib.h>
#include "openvas_ssh_login.h"

int
lsc_user_all_create (const gchar *name,
                     const gchar *password,
                     gchar **public_key,
                     gchar **private_key,
                     void **rpm, gsize *rpm_size,
                     void **deb, gsize *deb_size,
                     void **exe, gsize *exe_size);

#endif /* _OPENVASMD_LSC_USER_H */
