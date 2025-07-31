/* Copyright (C) 2020-2022 Greenbone AG
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

/**
 * @file
 * @brief GVM management layer: License information headers.
 *
 * Headers for non-SQL license information code for the GVM management layer.
 */

#include <glib.h>

#ifdef HAS_LIBTHEIA
#include <theia/client.h>
#else
#include "theia_dummy.h"
#endif

/* Actions */

int
manage_update_license_file (const char *, char **);

int
manage_get_license (gchar **, theia_license_t **);
