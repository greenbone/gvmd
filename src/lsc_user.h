/* OpenVAS Manager
 * $Id$
 * Description: LSC user credentials package generation.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * Felix Wolfsteller <felix.wolfsteller@greenbone.net>
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

int
lsc_user_keys_create (const gchar *, gchar **, gchar **);

int
lsc_user_rpm_recreate (const gchar *, const gchar *,
                       void **, gsize *);

int
lsc_user_deb_recreate (const gchar *, const char *, gsize, void **, gsize *);

int
lsc_user_exe_recreate (const gchar *, const gchar *, void **, gsize *);

#endif /* _OPENVASMD_LSC_USER_H */
