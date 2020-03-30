/* Copyright (C) 2009-2018 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * @file lsc_user.h
 * @brief LSC user credentials package generation.
 */

#ifndef _GVMD_LSC_USER_H
#define _GVMD_LSC_USER_H

#include <glib.h>

int
lsc_user_keys_create (const gchar *, gchar **);

int
lsc_user_rpm_recreate (const gchar *, const gchar *,
                       void **, gsize *);

int
lsc_user_deb_recreate (const gchar *, const char *, const char *,
                       void **, gsize *);

int
lsc_user_exe_recreate (const gchar *, const gchar *, void **, gsize *);

#endif /* not _GVMD_LSC_USER_H */
