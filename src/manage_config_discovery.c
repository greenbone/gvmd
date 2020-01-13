/* Copyright (C) 2013-2018 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

/**
 * @file  manage_config_discovery.c
 * @brief GVM management layer: Predefined config: Discovery
 *
 * This file contains the creation of the predefined config Discovery.
 */

#include "manage.h"
#include "sql.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md   main"

/**
 * @brief Ensure the Discovery config is up to date.
 *
 * @param[in]  uuid  UUID of config.
 *
 * @return 0 success, -1 error.
 */
int
check_config_discovery (const char *uuid)
{
  /* Check preferences. */

  sql ("UPDATE config_preferences SET value = 'no'"
       " WHERE config = (SELECT id FROM configs WHERE uuid = '%s')"
       " AND type = 'PLUGINS_PREFS'"
       " AND name = '" OID_PING_HOST ":6:checkbox:Report about unrechable Hosts'"
       " AND value = 'yes';",
       uuid);

  update_config_preference (uuid,
                            "PLUGINS_PREFS",
                            OID_PING_HOST ":5:checkbox:"
                            "Mark unrechable Hosts as dead (not scanning)",
                            "yes",
                            TRUE);

  sql ("DELETE FROM nvt_selectors"
       " WHERE family_or_nvt = '1.3.6.1.4.1.25623.1.0.90011'"
       " AND type = %d"
       " AND name = (SELECT nvt_selector FROM configs WHERE uuid = '%s')",
       NVT_SELECTOR_TYPE_NVT,
       uuid);

  return 0;
}
